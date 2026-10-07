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
#include "clang/AST/Expr.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

bool containsCallToRole(const Stmt *S, StringRef Role, CheckerContext &C) {
  if (!S)
    return false;

  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (knighter::callExprIsRole(CE, Role, C.getASTContext()))
      return true;
  }

  for (const Stmt *Child : S->children()) {
    if (Child && containsCallToRole(Child, Role, C))
      return true;
  }

  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Publishing before Initialization",
                       "API Misuse")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *Cond = IS->getCond();
  if (!containsCallToRole(Cond, "container_insert", C))
    return;

  const Stmt *Then = IS->getThen();
  if (!Then)
    return;

  if (!containsCallToRole(Then, "init", C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Publishing object before initialization can leave an incomplete registry entry",
      N);
  Report->addRange(IS->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects publishing an object into a registry before it is fully initialized",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "container_insert": {
    "names": ["luaL_newmetatable", "lua_setfield"],
    "description": "inserts or publishes an object into a persistent registry/container so later lookups can observe it; it must happen after the object is fully initialized"
  },
  "init": {
    "names": ["luaL_setfuncs"],
    "description": "populates or initializes an already created object and may raise a non-local error, so it must complete before publication"
  }
}
*/
