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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/APSInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks divisor memory regions that have been proven non-zero on the
// current path.
REGISTER_MAP_WITH_PROGRAMSTATE(CheckedDivisorMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker
    : public Checker<check::PreStmt<BinaryOperator>, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Division by zero", "Arithmetic Error")) {}

  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportDivisionByZero(const BinaryOperator *BO, CheckerContext &C,
                            bool definite) const;

  ProgramStateRef markDivisorChecked(ProgramStateRef State, const Expr *E,
                                     CheckerContext &C) const;

  ProgramStateRef markCheckedInCondition(const Expr *Cond, CheckerContext &C,
                                         ProgramStateRef State) const;
};

} // end anonymous namespace

void SAGenTestChecker::reportDivisionByZero(const BinaryOperator *BO,
                                            CheckerContext &C,
                                            bool definite) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  const char *Msg =
      definite
          ? "Division by zero"
          : "Potential division by zero: divisor may be zero and is not checked";

  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO,
                                    CheckerContext &C) const {
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_Div && Op != BO_Rem)
    return;

  if (!BO->getLHS()->getType()->isIntegerType() ||
      !BO->getRHS()->getType()->isIntegerType())
    return;

  const Expr *Divisor = BO->getRHS();
  if (!Divisor)
    return;

  // Constant zero divisor: report a definite division by zero.
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, Divisor, C)) {
    if (EvalRes.isZero())
      reportDivisionByZero(BO, C, true);
    return;
  }

  // Otherwise, check whether this divisor region was proven non-zero.
  const Expr *DivisorNoParens = Divisor->IgnoreParens();
  const MemRegion *MR = getMemRegionFromExpr(DivisorNoParens, C);
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<CheckedDivisorMap>(MR);
  if (!Checked || *Checked == false)
    reportDivisionByZero(BO, C, false);
}

ProgramStateRef SAGenTestChecker::markDivisorChecked(ProgramStateRef State,
                                                     const Expr *E,
                                                     CheckerContext &C) const {
  if (!E)
    return State;

  const Expr *Div = E->IgnoreParens();
  const MemRegion *MR = getMemRegionFromExpr(Div, C);
  if (!MR)
    return State;

  MR = MR->getBaseRegion();
  if (!MR)
    return State;

  return State->set<CheckedDivisorMap>(MR, true);
}

ProgramStateRef SAGenTestChecker::markCheckedInCondition(
    const Expr *Cond, CheckerContext &C, ProgramStateRef State) const {
  if (!Cond)
    return State;

  Cond = Cond->IgnoreParens();

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    BinaryOperator::Opcode Op = BO->getOpcode();

    // For logical AND, both sides hold, so recurse into both.
    if (Op == BO_LAnd) {
      State = markCheckedInCondition(BO->getLHS(), C, State);
      State = markCheckedInCondition(BO->getRHS(), C, State);
      return State;
    }

    // Comparisons that imply the divisor is non-zero.
    if (Op == BO_NE || Op == BO_GT || Op == BO_GE) {
      const Expr *LHS = BO->getLHS()->IgnoreParens();
      const Expr *RHS = BO->getRHS()->IgnoreParens();

      llvm::APSInt LVal, RVal;
      bool LConst = EvaluateExprToInt(LVal, LHS, C);
      bool RConst = EvaluateExprToInt(RVal, RHS, C);

      const Expr *Divisor = nullptr;

      if (Op == BO_NE) {
        // div != 0
        if (LConst && LVal.isZero())
          Divisor = RHS;
        else if (RConst && RVal.isZero())
          Divisor = LHS;
      } else if (Op == BO_GT) {
        // div > 0
        if (RConst && RVal.isZero())
          Divisor = LHS;
      } else if (Op == BO_GE) {
        // div >= 1
        if (RConst && RVal.isOne())
          Divisor = LHS;
      }

      if (Divisor)
        State = markDivisorChecked(State, Divisor, C);
    }
  } else if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    // Conservative handling of !div: suppress reports on both branches.
    if (UO->getOpcode() == UO_LNot)
      State = markDivisorChecked(State, UO->getSubExpr(), C);
  } else {
    // Implicit non-zero check, e.g. if (div) { ... }
    State = markDivisorChecked(State, Cond, C);
  }

  return State;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();
  State = markCheckedInCondition(CondE, C, State);
  C.addTransition(State);
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects division by zero caused by an unchecked divisor",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
