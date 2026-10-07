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
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(OwnedPtrMap, const MemRegion *, bool)

namespace {

static const MemRegion *getBaseRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

static void collectNonNullExprs(const Expr *E, ASTContext &Ctx,
                                llvm::SmallVectorImpl<const Expr *> &Out) {
  if (!E)
    return;

  E = E->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      collectNonNullExprs(BO->getLHS(), Ctx, Out);
      collectNonNullExprs(BO->getRHS(), Ctx, Out);
      return;
    }
    if (BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LHSIsNull =
          LHS->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull =
          RHS->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && !RHSIsNull) {
        Out.push_back(RHS);
        return;
      }
      if (RHSIsNull && !LHSIsNull) {
        Out.push_back(LHS);
        return;
      }
    }
    return;
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *BO = dyn_cast<BinaryOperator>(Sub)) {
        if (BO->getOpcode() == BO_EQ) {
          const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
          const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
          bool LHSIsNull =
              LHS->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
          bool RHSIsNull =
              RHS->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
          if (LHSIsNull && !RHSIsNull) {
            Out.push_back(RHS);
            return;
          }
          if (RHSIsNull && !LHSIsNull) {
            Out.push_back(LHS);
            return;
          }
        }
      }
    }
    return;
  }

  if (E->getType()->isAnyPointerType()) {
    Out.push_back(E);
  }
}

static void collectContainerInsertCalls(
    const Stmt *S, llvm::SmallVectorImpl<const CallExpr *> &Calls) {
  if (!S)
    return;

  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (knighter::declIsRole(FD, "container_insert")) {
        Calls.push_back(CE);
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    collectContainerInsertCalls(Child, Calls);
  }
}

static bool hasDeallocatorForRegion(const Stmt *S, const MemRegion *SourceReg,
                                    CheckerContext &C) {
  if (!S || !SourceReg)
    return false;

  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (knighter::declIsRole(FD, "deallocator")) {
        for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
          const MemRegion *ArgReg = getBaseRegionFromExpr(CE->getArg(i), C);
          if (ArgReg && ArgReg == SourceReg)
            return true;
        }
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (hasDeallocatorForRegion(Child, SourceReg, C))
      return true;
  }
  return false;
}

class SAGenTestChecker
    : public Checker<eval::Call, check::PostCall, check::Bind,
                     check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory Leak", "Memory Management")) {}

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                 CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

bool SAGenTestChecker::evalCall(const CallEvent &Call,
                                CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "allocator") &&
      !knighter::callIsRole(Call, "duplicator"))
    return false;

  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  if (!OriginExpr->getType()->isAnyPointerType())
    return false;

  SValBuilder &SVB = C.getSValBuilder();
  const LocationContext *LCtx = C.getLocationContext();
  DefinedSVal RetVal =
      SVB.getConjuredHeapSymbolVal(OriginExpr, LCtx, C.blockCount())
          .castAs<DefinedSVal>();

  ProgramStateRef State = C.getState();
  State = State->BindExpr(OriginExpr, LCtx, RetVal);
  C.addTransition(State);
  return true;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "allocator") &&
      !knighter::callIsRole(Call, "duplicator"))
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *RetReg = Call.getReturnValue().getAsRegion();
  if (!RetReg)
    return;

  RetReg = RetReg->getBaseRegion();
  State = State->set<OwnedPtrMap>(RetReg, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  const MemRegion *LocR = Loc.getAsRegion();
  if (!LocR)
    return;
  LocR = LocR->getBaseRegion();

  ProgramStateRef State = C.getState();

  const MemRegion *ValR = Val.getAsRegion();
  bool ValOwned = false;
  if (ValR) {
    ValR = ValR->getBaseRegion();
    const bool *Owned = State->get<OwnedPtrMap>(ValR);
    ValOwned = Owned && *Owned;
  }

  if (ValOwned) {
    State = State->set<OwnedPtrMap>(LocR, true);
  } else {
    State = State->remove<OwnedPtrMap>(LocR);
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  llvm::SmallVector<const Expr *, 4> NonNullExprs;
  collectNonNullExprs(CondE, C.getASTContext(), NonNullExprs);
  if (NonNullExprs.empty())
    return;

  llvm::SmallVector<const MemRegion *, 4> NonNullRegions;
  for (const Expr *E : NonNullExprs) {
    const MemRegion *MR = getBaseRegionFromExpr(E, C);
    if (MR) {
      bool Found = false;
      for (const MemRegion *R : NonNullRegions) {
        if (R == MR) {
          Found = true;
          break;
        }
      }
      if (!Found)
        NonNullRegions.push_back(MR);
    }
  }
  if (NonNullRegions.empty())
    return;

  const Stmt *Then = IS->getThen();
  if (!Then)
    return;

  llvm::SmallVector<const CallExpr *, 4> InsertCalls;
  collectContainerInsertCalls(Then, InsertCalls);
  if (InsertCalls.empty())
    return;

  for (const CallExpr *CE : InsertCalls) {
    int SourceIdx = -1;
    const MemRegion *SourceReg = nullptr;

    for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
      const Expr *Arg = CE->getArg(i);
      const MemRegion *ArgReg = getBaseRegionFromExpr(Arg, C);
      if (!ArgReg)
        continue;

      const bool *Owned = State->get<OwnedPtrMap>(ArgReg);
      if (Owned && *Owned) {
        SourceIdx = (int)i;
        SourceReg = ArgReg;
        break;
      }
    }
    if (SourceIdx < 0)
      continue;

    bool DestFound = false;
    for (unsigned j = 0; j < CE->getNumArgs(); ++j) {
      if ((int)j == SourceIdx)
        continue;

      const Expr *Arg = CE->getArg(j);
      const MemRegion *ArgReg = getBaseRegionFromExpr(Arg, C);
      if (!ArgReg)
        continue;

      for (const MemRegion *NNR : NonNullRegions) {
        if (ArgReg == NNR) {
          DestFound = true;
          break;
        }
      }
      if (DestFound)
        break;
    }
    if (!DestFound)
      continue;

    const Stmt *Else = IS->getElse();
    if (!hasDeallocatorForRegion(Else, SourceReg, C)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "Potential leak: owned object not freed when container insert is "
          "skipped",
          N);
      Report->addRange(CE->getSourceRange());
      C.emitReport(std::move(Report));
      break;
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing deallocator when an owned object is conditionally "
      "inserted into a container",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {
    "names": ["triggerStepAllocate", "sqlite3SelectNew", "sqlite3SrcListAppendFromTerm", "sqlite3SrcListDup"],
    "description": "returns a newly allocated object owned by the caller; may return NULL on failure."
  },
  "duplicator": {
    "names": ["sqlite3SrcListDup", "sqlite3ExprListDup", "sqlite3ExprDup"],
    "description": "returns a newly allocated copy owned by the caller."
  },
  "deallocator": {
    "names": ["sqlite3SrcListDelete", "sqlite3ExprDelete", "sqlite3ExprListDelete"],
    "description": "frees an owned object; the pointer must not be used afterwards."
  },
  "container_insert": {
    "names": ["sqlite3SrcListAppendList"],
    "description": "appends/transfers ownership of a source object into a destination container; if not executed, the caller must free the source."
  }
}
*/
