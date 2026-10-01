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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/ASTContext.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::PreStmt<ArraySubscriptExpr>,
                                         check::PreStmt<CXXOperatorCallExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Buffer underflow", "BufferUnderflow")) {}

  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
  void checkPreStmt(const CXXOperatorCallExpr *OCE, CheckerContext &C) const;

private:
  void checkSubscript(const Expr *Index, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE,
                                    CheckerContext &C) const {
  checkSubscript(ASE->getIdx(), C);
}

void SAGenTestChecker::checkPreStmt(const CXXOperatorCallExpr *OCE,
                                    CheckerContext &C) const {
  if (OCE->getOperator() == OO_Subscript && OCE->getNumArgs() == 2) {
    checkSubscript(OCE->getArg(1), C);
  }
}

void SAGenTestChecker::checkSubscript(const Expr *Index,
                                      CheckerContext &C) const {
  if (!Index)
    return;

  // Strip parentheses and implicit casts.
  Index = Index->IgnoreParenImpCasts();

  const auto *BO = dyn_cast<BinaryOperator>(Index);
  if (!BO || BO->getOpcode() != BO_Sub)
    return;

  // Check if RHS is integer constant 1.
  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, BO->getRHS(), C))
    return;
  if (EvalRes != 1)
    return;

  const Expr *CountExpr = BO->getLHS();
  if (!CountExpr->getType()->isIntegerType())
    return;

  ProgramStateRef State = C.getState();
  SVal CountSVal = C.getSVal(CountExpr);
  if (CountSVal.isUnknown())
    return;

  SVal ZeroSVal = C.getSValBuilder().makeZeroVal(CountExpr->getType());
  SVal GTSVal = C.getSValBuilder().evalBinOp(
      State, BO_GT, CountSVal, ZeroSVal, C.getASTContext().BoolTy);

  auto Cond = GTSVal.getAs<DefinedSVal>();
  if (!Cond)
    return;

  // If there is a feasible path where CountExpr <= 0, then CountExpr may be zero.
  if (State->assume(*Cond, false)) {
    // Report bug.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Buffer underflow: index may be zero in container[index - 1]", N);
    report->addRange(Index->getSourceRange());
    C.emitReport(std::move(report));
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects buffer underflow when accessing container[index - 1] without checking index > 0",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
