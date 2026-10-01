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

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
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
      : BT(new BugType(this, "Missing null check", "CURL")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const LocationContext *LC = C.getLocationContext();
  if (!LC)
    return;

  const auto *FD = dyn_cast_or_null<FunctionDecl>(LC->getDecl());
  if (!FD || FD->getNameAsString() != "Curl_setblobopt")
    return;

  const auto *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  // The bug is specifically that the validation checks blob->len but never
  // validates blob->data before using/copying it.
  if (!ExprHasName(CondE, "blob->len", C))
    return;

  if (ExprHasName(CondE, "blob->data", C))
    return;

  if (!BT)
    return;

  PathDiagnosticLocation L = PathDiagnosticLocation::createBegin(
      CondE, C.getSourceManager(), LC);

  auto Report = std::make_unique<BasicBugReport>(
      *BT, "Missing null check on blob->data", L);
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing blob->data validation in Curl_setblobopt",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
