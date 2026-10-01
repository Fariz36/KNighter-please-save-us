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

#include "clang/AST/ExprCXX.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/OperationKinds.h"
#include "clang/Basic/OperatorKinds.h"
#include "llvm/ADT/APSInt.h"
#include <memory>
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::PreStmt<ArraySubscriptExpr>,
                                        check::PreStmt<CXXOperatorCallExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Buffer underflow", "Memory safety")) {}

  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
  void checkPreStmt(const CXXOperatorCallExpr *OCE, CheckerContext &C) const;

private:
  void checkIndexExpr(const Expr *IdxExpr, const Stmt *S,
                      CheckerContext &C) const;
  void reportUnderflow(const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE,
                                    CheckerContext &C) const {
  if (!ASE)
    return;
  checkIndexExpr(ASE->getIdx(), ASE, C);
}

void SAGenTestChecker::checkPreStmt(const CXXOperatorCallExpr *OCE,
                                    CheckerContext &C) const {
  if (!OCE)
    return;
  if (OCE->getOperator() != OO_Subscript)
    return;
  if (OCE->getNumArgs() == 0)
    return;

  // The index is the last argument to operator[].
  const Expr *Idx = OCE->getArg(OCE->getNumArgs() - 1);
  checkIndexExpr(Idx, OCE, C);
}

void SAGenTestChecker::checkIndexExpr(const Expr *IdxExpr,
                                      const Stmt *S,
                                      CheckerContext &C) const {
  if (!IdxExpr)
    return;

  const Expr *Idx = IdxExpr->IgnoreParenImpCasts();

  // We are looking for an expression of the form (size - 1).
  const auto *BO = dyn_cast<BinaryOperator>(Idx);
  if (!BO || BO->getOpcode() != BO_Sub)
    return;

  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  llvm::APSInt One;
  if (!EvaluateExprToInt(One, RHS, C) || One.getSExtValue() != 1)
    return;

  const Expr *SizeExpr = BO->getLHS()->IgnoreParenImpCasts();
  if (!SizeExpr->getType()->isIntegerType())
    return;

  ProgramStateRef State = C.getState();
  SVal SizeVal = State->getSVal(SizeExpr, C.getLocationContext());
  if (SizeVal.isUnknown() || SizeVal.isUndef())
    return;

  std::optional<DefinedSVal> SizeDVal = SizeVal.getAs<DefinedSVal>();
  if (!SizeDVal)
    return;

  // If the size can be zero on any path, then size - 1 underflows.
  ProgramStateRef ZeroState = State->assume(*SizeDVal, false);
  if (!ZeroState)
    return;

  reportUnderflow(S, C);
}

void SAGenTestChecker::reportUnderflow(const Stmt *S,
                                       CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Buffer underflow: index is size - 1 but size may be zero", N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects buffer underflow when indexing size - 1 without checking size > 0",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
