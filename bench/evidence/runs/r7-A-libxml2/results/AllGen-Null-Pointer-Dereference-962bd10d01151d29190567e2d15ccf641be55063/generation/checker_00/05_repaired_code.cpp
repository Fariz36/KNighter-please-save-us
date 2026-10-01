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

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Map from a parameter declaration to whether it has been checked for NULL.
// Value true means the parameter is known to be non-NULL on the current path.
REGISTER_MAP_WITH_PROGRAMSTATE(CheckedPtrParams, const ParmVarDecl *, bool)

namespace {

class SAGenTestChecker : public Checker<
    check::BeginFunction,
    check::BranchCondition,
    eval::Assume,
    check::PreStmt<UnaryOperator>,
    check::PreStmt<ArraySubscriptExpr>
> {
  mutable std::unique_ptr<BugType> BT;

  // Pending NULL check information set by checkBranchCondition and consumed
  // by evalAssume.
  mutable const ParmVarDecl *CurrentNullCheckParam = nullptr;
  mutable bool CurrentNonNullWhenAssumption = false;
  mutable bool HasPendingNullCheck = false;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL pointer check",
                       "Null Pointer Dereference")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond,
                             bool Assumption) const;
  void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const;
  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;

private:
  const ParmVarDecl *getParmVarDeclFromExpr(const Expr *E) const;
  void reportNullDeref(const ParmVarDecl *PVD, const Stmt *S,
                       CheckerContext &C) const;
};

const ParmVarDecl *SAGenTestChecker::getParmVarDeclFromExpr(
    const Expr *E) const {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
      if (PVD->getType()->isPointerType())
        return PVD;
    }
  }
  return nullptr;
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();
  const Decl *D = LCtx->getDecl();
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  for (const ParmVarDecl *PVD : FD->parameters()) {
    if (PVD->getType()->isPointerType()) {
      State = State->set<CheckedPtrParams>(PVD, false);
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  // Reset pending information at the start of each branch condition.
  HasPendingNullCheck = false;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenImpCasts();
  ProgramStateRef State = C.getState();

  const ParmVarDecl *PVD = nullptr;
  bool NonNullWhen = false; // assumption value that implies non-NULL

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      PVD = getParmVarDeclFromExpr(Sub);
      if (PVD)
        NonNullWhen = false; // !ptr is true when ptr is NULL, non-NULL when false
    }
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSIsNull = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull && !RHSIsNull) {
        PVD = getParmVarDeclFromExpr(RHS);
      } else if (RHSIsNull && !LHSIsNull) {
        PVD = getParmVarDeclFromExpr(LHS);
      }

      if (PVD) {
        if (Op == BO_EQ)
          NonNullWhen = false; // ptr == NULL -> non-NULL when false
        else
          NonNullWhen = true; // ptr != NULL -> non-NULL when true
      }
    }
  } else {
    PVD = getParmVarDeclFromExpr(CondE);
    if (PVD)
      NonNullWhen = true; // if (ptr)
  }

  if (PVD) {
    HasPendingNullCheck = true;
    CurrentNullCheckParam = PVD;
    CurrentNonNullWhenAssumption = NonNullWhen;
  }
}

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal,
                                             bool Assumption) const {
  if (HasPendingNullCheck && Assumption == CurrentNonNullWhenAssumption) {
    State = State->set<CheckedPtrParams>(CurrentNullCheckParam, true);
    HasPendingNullCheck = false; // clear after applying
  }
  return State;
}

void SAGenTestChecker::checkPreStmt(const UnaryOperator *UO,
                                    CheckerContext &C) const {
  if (UO->getOpcode() != UO_Deref)
    return;

  const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
  const ParmVarDecl *PVD = getParmVarDeclFromExpr(Sub);
  if (!PVD)
    return;

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<CheckedPtrParams>(PVD);
  if (Checked && *Checked)
    return;

  reportNullDeref(PVD, UO, C);
}

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE,
                                    CheckerContext &C) const {
  const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
  const ParmVarDecl *PVD = getParmVarDeclFromExpr(Base);
  if (!PVD)
    return;

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<CheckedPtrParams>(PVD);
  if (Checked && *Checked)
    return;

  reportNullDeref(PVD, ASE, C);
}

void SAGenTestChecker::reportNullDeref(const ParmVarDecl *PVD, const Stmt *S,
                                       CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Dereference of pointer parameter without NULL check", N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereferences of pointer parameters without NULL checks",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
