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
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::BranchCondition> {
   mutable std::unique_ptr<BugType> BT;

public:
   SAGenTestChecker()
       : BT(new BugType(this, "Registry Entry Published Before Initialization",
                        "Imperfect Initialization")) {}

   void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                           CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenImpCasts();

  const CallExpr *CreateCall = dyn_cast<CallExpr>(CondE);
  if (!CreateCall)
    return;

  const FunctionDecl *CreateFD = CreateCall->getDirectCallee();
  if (!CreateFD)
    return;

  // The condition must be a combined lookup+create+publish API.
  if (!knighter::declIsRole(CreateFD, "allocator") ||
      !knighter::declIsRole(CreateFD, "container_insert"))
    return;

  const IfStmt *If = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!If)
    return;

  const Stmt *Then = If->getThen();
  if (!Then)
    return;

  const CallExpr *InitCall = findSpecificTypeInChildren<CallExpr>(Then);
  if (!InitCall)
    return;

  const FunctionDecl *InitFD = InitCall->getDirectCallee();
  if (!InitFD)
    return;

  if (!knighter::declIsRole(InitFD, "init"))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Registry entry published before initialization", N);
  Report->addRange(Condition->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects registry entries published before initialization",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {
    "names": ["luaL_newmetatable", "luaL_newlibtable"],
    "description": "creates a new object or memory region; may or may not publish it into a container"
  },
  "container_insert": {
    "names": ["luaL_newmetatable", "lua_setfield"],
    "description": "stores an object into a container or registry, making it visible to later lookups"
  },
  "lookup": {
    "names": ["luaL_newmetatable", "luaL_getmetatable"],
    "description": "checks whether a key already exists in a container or registry, usually without modifying it"
  },
  "init": {
    "names": ["luaL_setfuncs"],
    "description": "initializes an object's contents and may fail or raise an error"
  }
}
*/
