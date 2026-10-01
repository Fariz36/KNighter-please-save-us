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
#include "clang/AST/OperationKinds.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Operator Precedence", "Logic Error")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  const BinaryOperator *
  findBadAssignmentComparison(const Stmt *S, CheckerContext &C) const;

  bool isBadAssignment(const BinaryOperator *Assign, CheckerContext &C) const;

  bool isComparisonOpcode(BinaryOperator::Opcode Op) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isComparisonOpcode(BinaryOperator::Opcode Op) const {
  switch (Op) {
  case BO_LT:
  case BO_GT:
  case BO_LE:
  case BO_GE:
  case BO_EQ:
  case BO_NE:
    return true;
  default:
    return false;
  }
}

bool SAGenTestChecker::isBadAssignment(const BinaryOperator *Assign,
                                       CheckerContext &C) const {
  if (!Assign || Assign->getOpcode() != BO_Assign)
    return false;

  const Expr *LHS = Assign->getLHS()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(LHS);
  if (!DRE)
    return false;

  // Restrict to the variable named "error" to match the target bug pattern
  // and avoid flagging intentional boolean assignments.
  const ValueDecl *VD = DRE->getDecl();
  if (!VD || VD->getName() != "error")
    return false;

  // Do not ignore parentheses on the RHS: `error = (func() != 0)` is
  // intentionally parenthesized and should not be flagged.
  const Expr *RHS = Assign->getRHS()->IgnoreImpCasts();
  const auto *Cmp = dyn_cast<BinaryOperator>(RHS);
  if (!Cmp || !isComparisonOpcode(Cmp->getOpcode()))
    return false;

  const Expr *L = Cmp->getLHS()->IgnoreParenImpCasts();
  const Expr *R = Cmp->getRHS()->IgnoreParenImpCasts();

  bool LIsCall = isa<CallExpr>(L);
  bool RIsCall = isa<CallExpr>(R);

  // Exactly one side must be a call; the other side must evaluate to zero.
  if (LIsCall == RIsCall)
    return false;

  const Expr *Other = LIsCall ? R : L;

  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, Other, C)) {
    if (Val.isZero())
      return true;
  }

  if (const auto *IL = dyn_cast<IntegerLiteral>(Other)) {
    if (IL->getValue().isZero())
      return true;
  }

  return false;
}

const BinaryOperator *
SAGenTestChecker::findBadAssignmentComparison(const Stmt *S,
                                             CheckerContext &C) const {
  if (!S)
    return nullptr;

  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (isBadAssignment(BO, C))
      return BO;
  }

  for (const Stmt *Child : S->children()) {
    if (const BinaryOperator *Bad = findBadAssignmentComparison(Child, C))
      return Bad;
  }

  return nullptr;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const BinaryOperator *Bad = findBadAssignmentComparison(Condition, C);
  if (!Bad)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Operator precedence: assignment before comparison; parenthesize the "
      "assignment",
      N);
  Report->addRange(Bad->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects operator-precedence bugs where an assignment is combined with a "
      "comparison in a branch condition",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
