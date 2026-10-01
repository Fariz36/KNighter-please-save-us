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

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker
    : public Checker<check::PreStmt<UnaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Misuse of memcmp", "API Misuse")) {}

  void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const;

private:
  bool isMemcmpCall(const CallExpr *CE) const;
};

bool SAGenTestChecker::isMemcmpCall(const CallExpr *CE) const {
  if (!CE)
    return false;

  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return false;

  StringRef Name = FD->getName();
  return Name == "memcmp" || Name == "__builtin_memcmp";
}

void SAGenTestChecker::checkPreStmt(const UnaryOperator *UO,
                                    CheckerContext &C) const {
  if (!UO || UO->getOpcode() != UO_LNot)
    return;

  const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
  const auto *Inner = dyn_cast<UnaryOperator>(Sub);
  if (!Inner || Inner->getOpcode() != UO_LNot)
    return;

  const Expr *CallSub = Inner->getSubExpr()->IgnoreParenImpCasts();
  const auto *CE = dyn_cast<CallExpr>(CallSub);
  if (!CE)
    return;

  if (!isMemcmpCall(CE))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Double negation of memcmp() inverts equality check; use memcmp(...) == 0 instead.",
      N);
  Report->addRange(UO->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double negation misuse of memcmp() as an equality predicate",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
