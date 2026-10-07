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
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks objects that have been passed to a container_remove call on the
// current path.
REGISTER_MAP_WITH_PROGRAMSTATE(RemovedMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Deallocator called on linked object",
                       "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportDeallocatorWithoutRemove(const CallEvent &Call,
                                      CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // 1. container_remove: mark the object as removed from its container.
  if (knighter::callIsRole(Call, "container_remove")) {
    if (Call.getNumArgs() < 1)
      return;

    SVal ArgVal = Call.getArgSVal(0);
    const MemRegion *MR = ArgVal.getAsRegion();
    if (!MR)
      return;

    MR = MR->getBaseRegion();
    if (!MR)
      return;

    State = State->set<RemovedMap>(MR, true);
    C.addTransition(State);
    return;
  }

  // 2. deallocator: only check inside a container_insert function, and only
  //    when the freed argument is one of the function's parameters.
  if (!knighter::callIsRole(Call, "deallocator"))
    return;

  const Decl *D = C.getCurrentAnalysisDeclContext()->getDecl();
  if (!D)
    return;

  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !knighter::declIsRole(FD, "container_insert"))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;

  ArgExpr = ArgExpr->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(ArgExpr);
  if (!DRE)
    return;

  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD)
    return;

  if (PVD->getDeclContext() != static_cast<const DeclContext *>(FD))
    return;

  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  const bool *Removed = State->get<RemovedMap>(MR);
  if (Removed && *Removed)
    return;

  reportDeallocatorWithoutRemove(Call, C);
}

void SAGenTestChecker::reportDeallocatorWithoutRemove(
    const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "deallocator called on linked object without prior container_remove",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects deallocator called on linked object without prior container_remove",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "deallocator": {"names": ["xmlFreeNode"], "description": "frees an object; the object must not be used afterwards"},
  "container_remove": {"names": ["xmlUnlinkNodeInternal"], "description": "removes an object from its container, unlinking it so it is no longer referenced by the container"},
  "container_insert": {"names": ["xmlAddChild"], "description": "inserts an object into a container; the object should be unlinked first if it is already linked"}
}
*/
