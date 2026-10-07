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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(UncheckedSourcePtrs, SymbolRef)

namespace {

class SAGenTestChecker
    : public Checker<check::BeginFunction,
                     check::BranchCondition,
                     check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Null Pointer Dereference", "Memory safety")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool isLoad, const Stmt *S,
                     CheckerContext &C) const;

private:
  const FunctionDecl *getCurrentDuplicator(CheckerContext &C) const;
  SymbolRef getPointeeSymbol(const ParmVarDecl *PVD, ProgramStateRef State,
                             CheckerContext &C) const;
  bool isParamRef(const Expr *E, const ParmVarDecl *PVD) const;
  bool isNullCheck(const Expr *Cond, const ParmVarDecl *PVD,
                   ASTContext &AC) const;
  void reportUncheckedDeref(SymbolRef Sym, const Stmt *S,
                            CheckerContext &C) const;
};

} // end anonymous namespace

const FunctionDecl *
SAGenTestChecker::getCurrentDuplicator(CheckerContext &C) const {
  const StackFrameContext *SF = C.getStackFrame();
  if (!SF)
    return nullptr;
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(SF->getDecl());
  if (FD && knighter::declIsRole(FD, "duplicator"))
    return FD;
  return nullptr;
}

SymbolRef SAGenTestChecker::getPointeeSymbol(const ParmVarDecl *PVD,
                                             ProgramStateRef State,
                                             CheckerContext &C) const {
  if (!PVD || !State)
    return nullptr;
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return nullptr;
  const VarRegion *VR = State->getRegion(PVD, LCtx);
  if (!VR)
    return nullptr;
  SVal V = State->getSVal(VR);
  const MemRegion *MR = V.getAsRegion();
  if (!MR)
    return nullptr;
  MR = MR->getBaseRegion();
  if (!MR)
    return nullptr;
  if (const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(MR))
    return SR->getSymbol();
  return nullptr;
}

bool SAGenTestChecker::isParamRef(const Expr *E,
                                  const ParmVarDecl *PVD) const {
  if (!E || !PVD)
    return false;
  E = E->IgnoreParenCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    const ValueDecl *VD = DRE->getDecl();
    return VD == PVD;
  }
  return false;
}

bool SAGenTestChecker::isNullCheck(const Expr *Cond, const ParmVarDecl *PVD,
                                   ASTContext &AC) const {
  if (!Cond || !PVD)
    return false;
  Cond = Cond->IgnoreParenCasts();

  // Bare pointer: if (p)
  if (isParamRef(Cond, PVD))
    return true;

  // !p
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot)
      return isParamRef(UO->getSubExpr(), PVD);
  }

  // p == NULL / p != NULL / p == 0 / p != 0
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHSIsNull =
          LHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull =
          RHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && isParamRef(RHS, PVD))
        return true;
      if (RHSIsNull && isParamRef(LHS, PVD))
        return true;
    }
  }

  return false;
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentDuplicator(C);
  if (!FD)
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (const ParmVarDecl *PVD : FD->parameters()) {
    if (!PVD->getType()->isPointerType())
      continue;

    SymbolRef Sym = getPointeeSymbol(PVD, State, C);
    if (!Sym)
      continue;

    if (!State->contains<UncheckedSourcePtrs>(Sym)) {
      State = State->add<UncheckedSourcePtrs>(Sym);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentDuplicator(C);
  if (!FD)
    return;

  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;
  ASTContext &AC = C.getASTContext();

  for (const ParmVarDecl *PVD : FD->parameters()) {
    if (!PVD->getType()->isPointerType())
      continue;

    if (!isNullCheck(Cond, PVD, AC))
      continue;

    SymbolRef Sym = getPointeeSymbol(PVD, State, C);
    if (Sym && State->contains<UncheckedSourcePtrs>(Sym)) {
      State = State->remove<UncheckedSourcePtrs>(Sym);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool isLoad, const Stmt *S,
                                     CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentDuplicator(C);
  if (!FD)
    return;
  if (!S)
    return;

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  const MemRegion *Base = MR->getBaseRegion();
  if (!Base)
    return;

  const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(Base);
  if (!SR)
    return;

  SymbolRef Sym = SR->getSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<UncheckedSourcePtrs>(Sym))
    return;

  reportUncheckedDeref(Sym, S, C);
}

void SAGenTestChecker::reportUncheckedDeref(SymbolRef Sym, const Stmt *S,
                                            CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "NULL pointer dereference: duplicator source pointer not checked",
      N);
  if (S)
    report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));

  ProgramStateRef State = C.getState();
  State = State->remove<UncheckedSourcePtrs>(Sym);
  C.addTransition(State);
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects NULL pointer dereference in duplicator functions when the "
      "source pointer is not checked before dereference",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "duplicator": {"names": ["curl_url_dup", "DUP"], "description": "function or macro that creates a copy of a source object; it must not dereference the source pointer before verifying it is non-null"},
  "allocator": {"names": ["curlx_calloc"], "description": "function that allocates memory and returns a pointer or NULL on failure"}
}
*/
