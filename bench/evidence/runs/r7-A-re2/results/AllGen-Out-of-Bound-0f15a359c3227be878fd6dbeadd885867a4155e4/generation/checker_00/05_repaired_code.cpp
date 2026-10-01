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
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/ExprCXX.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state is needed; the constraint manager already tracks
// path-sensitive constraints on symbolic values.

namespace {

class SAGenTestChecker
    : public Checker<check::PreCall, check::PreStmt<ArraySubscriptExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Buffer underflow", "Memory Error")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;

private:
  void checkIndexMinusOne(const Expr *Index, const Stmt *ReportStmt,
                          CheckerContext &C) const;
};

void SAGenTestChecker::checkIndexMinusOne(const Expr *Index,
                                          const Stmt *ReportStmt,
                                          CheckerContext &C) const {
  if (!Index)
    return;

  Index = Index->IgnoreParenImpCasts();

  // Match pattern: X - 1
  const auto *BO = dyn_cast<BinaryOperator>(Index);
  if (!BO || BO->getOpcode() != BO_Sub)
    return;

  const auto *IL =
      dyn_cast<IntegerLiteral>(BO->getRHS()->IgnoreParenImpCasts());
  if (!IL || IL->getValue() != 1)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();

  SVal LHSVal = C.getState()->getSVal(LHS, C.getLocationContext());
  SymbolRef Sym = LHSVal.getAsSymbol();
  if (!Sym)
    return;

  const llvm::APSInt *MinVal =
      C.getState()->getConstraintManager().getSymMinVal(C.getState(), Sym);

  // If the value is known to be strictly positive, the subtraction is safe.
  if (MinVal && MinVal->isStrictlyPositive())
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Buffer underflow: indexing with count-1 without checking count > 0",
      N);
  if (ReportStmt)
    Report->addRange(ReportStmt->getSourceRange());

  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const auto *OOE =
      dyn_cast_or_null<CXXOperatorCallExpr>(Call.getOriginExpr());
  if (!OOE || OOE->getOperator() != OO_Subscript)
    return;

  if (OOE->getNumArgs() < 2)
    return;

  const Expr *Index = OOE->getArg(1);
  checkIndexMinusOne(Index, OOE, C);
}

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE,
                                    CheckerContext &C) const {
  if (!ASE)
    return;

  const Expr *Index = ASE->getIdx();
  checkIndexMinusOne(Index, ASE, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects buffer underflow caused by indexing with count-1 without "
      "checking count > 0",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
