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
#include "clang/Lex/Lexer.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL check for blob->data",
                       "API Misuse")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const auto *FD =
      dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD || FD->getNameAsString() != "Curl_setblobopt")
    return;

  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  // The buggy condition validates blob->len but not blob->data.
  if (!ExprHasName(Cond, "blob->len", C))
    return;

  if (ExprHasName(Cond, "blob->data", C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing NULL check for blob->data", N);
  Report->addRange(Cond->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL check for blob->data in Curl_setblobopt", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
