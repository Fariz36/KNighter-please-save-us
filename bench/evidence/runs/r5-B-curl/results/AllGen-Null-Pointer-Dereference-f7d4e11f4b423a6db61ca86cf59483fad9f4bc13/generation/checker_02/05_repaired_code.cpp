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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker
    : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL Check",
                       "Curl API argument validation")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || FD->getName() != "Curl_setblobopt")
    return;

  const Expr *CondExpr = dyn_cast<Expr>(Condition);
  if (!CondExpr)
    return;

  const bool ChecksLen = ExprHasName(CondExpr, "blob->len", C);
  const bool ChecksData = ExprHasName(CondExpr, "blob->data", C);

  if (!ChecksLen || ChecksData)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Missing NULL check for 'blob->data' before use in Curl_setblobopt", N);
  Report->addRange(CondExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL check for blob->data in Curl_setblobopt",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
