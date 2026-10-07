#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

#include <algorithm>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program-state maps
REGISTER_MAP_WITH_PROGRAMSTATE(UntrustedSymbols, SymbolRef, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(NarrowUntrustedRegions, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(UnsafeCheckRegions, const MemRegion *, bool)

namespace {

class SAGenTestChecker
    : public Checker<check::PostCall, check::Bind, check::BranchCondition,
                     check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow in Bounds Check",
                       "Integer Overflow")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportUnsafeCopy(const CallEvent &Call, CheckerContext &C) const;
};

static bool isNarrowIntegerType(QualType QT, CheckerContext &C) {
  if (!QT->isIntegerType())
    return false;
  ASTContext &AC = C.getASTContext();
  return AC.getTypeSize(QT) < AC.getTypeSize(AC.getSizeType());
}

static bool stmtContainsRoleCall(const Stmt *S, StringRef Role) {
  if (!S)
    return false;

  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (knighter::declIsRole(FD, Role))
        return true;
    }
  }

  for (const Stmt *Child : S->children()) {
    if (stmtContainsRoleCall(Child, Role))
      return true;
  }
  return false;
}

static bool exprContainsNarrowUntrusted(const Expr *E, ProgramStateRef State,
                                        CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (const MemRegion *MR = State->getRegion(VD, C.getLocationContext())) {
        MR = MR->getBaseRegion();
        if (MR && State->get<NarrowUntrustedRegions>(MR))
          return true;
      }
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child)) {
      if (exprContainsNarrowUntrusted(ChildE, State, C))
        return true;
    }
  }
  return false;
}

static bool exprContainsSizeofOrConst(const Expr *E) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const UnaryExprOrTypeTraitExpr *UETT =
          dyn_cast<UnaryExprOrTypeTraitExpr>(E)) {
    if (UETT->getKind() == UETT_SizeOf)
      return true;
  }

  if (isa<IntegerLiteral>(E))
    return true;

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child)) {
      if (exprContainsSizeofOrConst(ChildE))
        return true;
    }
  }
  return false;
}

static void collectNarrowRegionsFromExpr(
    const Expr *E, ProgramStateRef State, CheckerContext &C,
    SmallVectorImpl<const MemRegion *> &Out) {
  if (!E)
    return;

  E = E->IgnoreParenImpCasts();

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (const MemRegion *MR = State->getRegion(VD, C.getLocationContext())) {
        MR = MR->getBaseRegion();
        if (MR && State->get<NarrowUntrustedRegions>(MR)) {
          if (std::find(Out.begin(), Out.end(), MR) == Out.end())
            Out.push_back(MR);
        }
      }
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child))
      collectNarrowRegionsFromExpr(ChildE, State, C, Out);
  }
}

static void findUnsafeAdds(const Expr *E, ProgramStateRef State,
                           CheckerContext &C,
                           SmallVectorImpl<const MemRegion *> &Out) {
  if (!E)
    return;

  E = E->IgnoreParenImpCasts();

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Add) {
      if (exprContainsNarrowUntrusted(BO, State, C) &&
          exprContainsSizeofOrConst(BO)) {
        collectNarrowRegionsFromExpr(BO, State, C, Out);
      }
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child))
      findUnsafeAdds(ChildE, State, C, Out);
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "parser_input"))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  if (SymbolRef Sym = RetVal.getAsSymbol()) {
    State = State->set<UntrustedSymbols>(Sym, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  const MemRegion *Dest = Loc.getAsRegion();
  if (!Dest)
    return;

  Dest = Dest->getBaseRegion();
  if (!Dest)
    return;

  ProgramStateRef State = C.getState();

  if (SymbolRef Sym = Val.getAsSymbol()) {
    if (State->get<UntrustedSymbols>(Sym)) {
      if (const TypedValueRegion *TVR = dyn_cast<TypedValueRegion>(Dest)) {
        if (isNarrowIntegerType(TVR->getValueType(), C)) {
          State = State->set<NarrowUntrustedRegions>(Dest, true);
        } else {
          State = State->remove<NarrowUntrustedRegions>(Dest);
        }
      }
    } else {
      State = State->remove<NarrowUntrustedRegions>(Dest);
    }
  } else {
    State = State->remove<NarrowUntrustedRegions>(Dest);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }
  CondE = CondE->IgnoreParenImpCasts();

  const IfStmt *If = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!If) {
    C.addTransition(State);
    return;
  }

  if (!stmtContainsRoleCall(If->getThen(), "error_setter")) {
    C.addTransition(State);
    return;
  }

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO) {
    C.addTransition(State);
    return;
  }

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GT && Op != BO_GE && Op != BO_LT && Op != BO_LE) {
    C.addTransition(State);
    return;
  }

  SmallVector<const MemRegion *, 4> Regions;
  findUnsafeAdds(BO->getLHS(), State, C, Regions);
  findUnsafeAdds(BO->getRHS(), State, C, Regions);

  for (const MemRegion *MR : Regions) {
    if (MR)
      State = State->set<UnsafeCheckRegions>(MR, true);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "buffer_copy"))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *Arg = Call.getArgExpr(i);
    if (!Arg)
      continue;

    SmallVector<const MemRegion *, 4> Regions;
    collectNarrowRegionsFromExpr(Arg, State, C, Regions);

    for (const MemRegion *MR : Regions) {
      if (State->get<UnsafeCheckRegions>(MR)) {
        reportUnsafeCopy(Call, C);
        return;
      }
    }
  }
}

void SAGenTestChecker::reportUnsafeCopy(const CallEvent &Call,
                                        CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "narrow untrusted length/offset bypasses bounds check before buffer copy",
      N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer-overflow-prone bounds checks involving narrow untrusted "
      "length/offset values before a buffer copy",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {
    "names": ["Curl_read16_le"],
    "description": "decodes untrusted input bytes into an integer length or offset value"
  },
  "buffer_copy": {
    "names": ["Curl_client_write"],
    "description": "consumes a buffer pointer and a length, assuming the length is within the buffer"
  },
  "error_setter": {
    "names": ["failf", "Curl_failf"],
    "description": "printf-style function that records or reports an error message"
  },
  "length_of": {
    "names": ["sizeof"],
    "description": "yields the byte size of a type or object, used as a constant in bounds-check arithmetic"
  }
}
*/
