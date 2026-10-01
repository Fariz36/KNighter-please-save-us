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
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::PreStmt<ReturnStmt>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "OrStrings() returns NULL", "Null Pointer")) {}

  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS,
                                    CheckerContext &C) const {
  if (!RS)
    return;

  const AnalysisDeclContext *ADC = C.getCurrentAnalysisDeclContext();
  if (!ADC)
    return;

  const auto *FD = dyn_cast<FunctionDecl>(ADC->getDecl());
  if (!FD)
    return;

  if (FD->getQualifiedNameAsString() != "re2::Prefilter::OrStrings")
    return;

  const Expr *RetExpr = RS->getRetValue();
  if (!RetExpr)
    return;

  RetExpr = RetExpr->IgnoreImplicit();
  if (!RetExpr)
    return;

  ProgramStateRef State = C.getState();
  if (!State)
    return;

  SVal RetVal = State->getSVal(RetExpr, C.getLocationContext());
  if (RetVal.isUnknownOrUndef())
    return;

  if (!RetVal.getAs<Loc>())
    return;

  if (!State->isNull(RetVal).isConstrainedTrue())
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "OrStrings() may return NULL; use Prefilter(NONE) for empty set.", N);
  Report->addRange(RS->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects re2::Prefilter::OrStrings returning NULL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
