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
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read", "Bounds checking")) {}

  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;

  const auto *ASE = dyn_cast<ArraySubscriptExpr>(S);
  if (!ASE)
    return;

  if (!ExprHasName(ASE, "NXT", C))
    return;

  const Expr *Idx = ASE->getIdx();
  if (!Idx)
    return;

  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, Idx, C) && EvalRes.isZero())
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked lookahead access in NXT macro", N);
  Report->addRange(ASE->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked lookahead accesses in the NXT macro",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
