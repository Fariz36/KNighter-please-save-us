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
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker
    : public Checker<check::PostStmt<UnaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Inverted memcmp comparison", "Security")) {}

  void checkPostStmt(const UnaryOperator *UO, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostStmt(const UnaryOperator *UO,
                                     CheckerContext &C) const {
  if (!UO || UO->getOpcode() != UO_LNot)
    return;

  const Expr *Inner = UO->getSubExpr()->IgnoreParenImpCasts();
  const auto *InnerUO = dyn_cast<UnaryOperator>(Inner);
  if (!InnerUO || InnerUO->getOpcode() != UO_LNot)
    return;

  const Expr *CE = InnerUO->getSubExpr()->IgnoreParenImpCasts();
  const auto *Call = dyn_cast<CallExpr>(CE);
  if (!Call)
    return;

  const FunctionDecl *FD = Call->getDirectCallee();
  if (!FD || FD->getName() != "memcmp")
    return;

  if (Call->getNumArgs() != 3)
    return;

  auto Report = std::make_unique<BasicBugReport>(
      *BT,
      "Inverted memcmp: use memcmp() == 0 for equality",
      PathDiagnosticLocation(UO, C.getSourceManager(),
                             C.getLocationContext()));
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects inverted equality checks using !!memcmp(...)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
