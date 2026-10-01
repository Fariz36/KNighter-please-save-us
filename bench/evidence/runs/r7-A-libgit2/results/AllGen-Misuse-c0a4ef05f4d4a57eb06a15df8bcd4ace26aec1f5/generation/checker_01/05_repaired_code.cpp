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

#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker
    : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Operator precedence bug", "C/C++")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void checkCondition(
      const Stmt *S, CheckerContext &C,
      llvm::SmallPtrSetImpl<const BinaryOperator *> &Reported) const;
};

static bool isComparisonOpcode(BinaryOperator::Opcode Op) {
  return Op == BO_EQ || Op == BO_NE || Op == BO_LT || Op == BO_GT ||
         Op == BO_LE || Op == BO_GE;
}

static bool isBuggyAssignmentComparison(const BinaryOperator *BO) {
  if (!BO || BO->getOpcode() != BO_Assign)
    return false;

  const Expr *RHS = BO->getRHS();
  if (!RHS)
    return false;

  // Do not ignore parentheses on the RHS. If the comparison is explicitly
  // parenthesized, the pattern is likely intentional.
  const auto *Cmp = dyn_cast<BinaryOperator>(RHS);
  if (!Cmp || !isComparisonOpcode(Cmp->getOpcode()))
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(LHS);
  if (!DRE)
    return false;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return false;

  QualType Ty = VD->getType();
  if (!Ty->isIntegerType() || Ty->isBooleanType())
    return false;

  const Expr *CmpLHS = Cmp->getLHS()->IgnoreParenImpCasts();
  const Expr *CmpRHS = Cmp->getRHS()->IgnoreParenImpCasts();
  if (!isa<CallExpr>(CmpLHS) && !isa<CallExpr>(CmpRHS))
    return false;

  return true;
}

void SAGenTestChecker::checkCondition(
    const Stmt *S, CheckerContext &C,
    llvm::SmallPtrSetImpl<const BinaryOperator *> &Reported) const {
  if (!S)
    return;

  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (isBuggyAssignmentComparison(BO) && Reported.insert(BO).second) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (N) {
        auto R = std::make_unique<PathSensitiveBugReport>(
            *BT,
            "operator precedence bug: assignment result used as comparison", N);
        R->addRange(BO->getSourceRange());
        C.emitReport(std::move(R));
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    checkCondition(Child, C, Reported);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  llvm::SmallPtrSet<const BinaryOperator *, 4> Reported;
  checkCondition(Condition, C, Reported);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects operator precedence bugs where an assignment is used as a "
      "comparison without parentheses",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
