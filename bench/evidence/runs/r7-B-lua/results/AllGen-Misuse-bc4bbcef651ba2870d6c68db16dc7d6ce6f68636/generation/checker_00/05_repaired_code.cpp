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

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

static const CallExpr *findCallTo(const Stmt *S, StringRef Name,
                                  CheckerContext &C) {
  if (!S)
    return nullptr;

  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (ExprHasName(CE, Name, C))
      return CE;
  }

  for (const Stmt *Child : S->children()) {
    if (const CallExpr *Found = findCallTo(Child, Name, C))
      return Found;
  }

  return nullptr;
}

namespace {
class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Metatable Registered Before Initialization",
                       "Lua API Misuse")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenImpCasts();

  const CallExpr *NewMetaCE = dyn_cast<CallExpr>(CondE);
  if (!NewMetaCE)
    return;

  if (!ExprHasName(NewMetaCE, "luaL_newmetatable", C))
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Stmt *Then = IS->getThen();
  if (!Then)
    return;

  const CallExpr *SetFuncsCE = findCallTo(Then, "luaL_setfuncs", C);
  if (!SetFuncsCE)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Metatable registered before initialization", N);
  report->addRange(SetFuncsCE->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects metatables registered before initialization via "
      "luaL_newmetatable",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
