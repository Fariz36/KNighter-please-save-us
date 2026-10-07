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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static const CallExpr *findCallToRole(const Stmt *S, StringRef Role) {
  if (!S)
    return nullptr;

  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (knighter::isRole(Role, FD->getName()))
        return CE;
    }
  }

  for (const Stmt *Child : S->children()) {
    if (const CallExpr *Found = findCallToRole(Child, Role))
      return Found;
  }

  return nullptr;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Non-atomic registry publication",
                       "API Misuse")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS || IS->getCond() != Condition)
    return;

  const CallExpr *CombinedCall =
      findCallToRole(Condition, "combined_create_and_publish");
  if (!CombinedCall)
    return;

  const CallExpr *InitCall =
      findCallToRole(IS->getThen(), "object_initializer");
  if (!InitCall)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Non-atomic registry publication: initialize before publishing", N);
  Report->addRange(CombinedCall->getSourceRange());

  PathDiagnosticLocation InitLoc = PathDiagnosticLocation::createBegin(
      InitCall, C.getSourceManager(), C.getLocationContext());
  Report->addNote(
      "Initialization may fail after the object is already in the registry",
      InitLoc);

  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects non-atomic publication of an object into a persistent registry",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "combined_create_and_publish": {
    "names": ["luaL_newmetatable"],
    "description": "creates a persistent object and immediately publishes it into a registry, before the caller can initialize it"
  },
  "object_initializer": {
    "names": ["luaL_setfuncs"],
    "description": "fallible initializer for a newly created object; it may raise/abort"
  },
  "persistent_registry_lookup": {
    "names": ["luaL_getmetatable"],
    "description": "safe lookup of an existing object in a persistent registry"
  },
  "object_allocator": {
    "names": ["luaL_newlibtable"],
    "description": "allocates a new object locally without publishing it"
  },
  "registry_store": {
    "names": ["lua_setfield"],
    "description": "publishes an object into a registry after initialization"
  },
  "registry_key": {
    "names": ["_UBOX*"],
    "description": "key under which the object is stored in the registry"
  }
}
*/
