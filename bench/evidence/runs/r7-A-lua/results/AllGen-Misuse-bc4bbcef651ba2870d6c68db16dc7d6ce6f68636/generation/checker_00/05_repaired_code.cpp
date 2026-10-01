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
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Lua API Misuse",
                       "Metatable registered before full initialization")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Check if this is a call to luaL_setfuncs
  if (!ExprHasName(Origin, "luaL_setfuncs", C))
    return;

  // Find the nearest enclosing if statement
  const IfStmt *If = findSpecificTypeInParents<IfStmt>(Origin, C);
  if (!If)
    return;

  // Get the condition, stripping parentheses and implicit casts
  const Expr *Cond = If->getCond();
  if (!Cond)
    return;
  Cond = Cond->IgnoreParenImpCasts();

  // Check if the condition is a direct call to luaL_newmetatable
  const CallExpr *CE = dyn_cast<CallExpr>(Cond);
  if (!CE)
    return;

  if (!ExprHasName(CE, "luaL_newmetatable", C))
    return;

  // Report the bug
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Metatable registered before full initialization", N);
  report->addRange(Origin->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of luaL_newmetatable followed by luaL_setfuncs "
      "which can leave an incomplete metatable in the registry",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
