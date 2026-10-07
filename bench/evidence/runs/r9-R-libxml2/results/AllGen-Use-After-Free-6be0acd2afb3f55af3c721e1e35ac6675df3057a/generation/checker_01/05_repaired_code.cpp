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
#include "knighter/roles.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;
using namespace llvm;

REGISTER_MAP_WITH_PROGRAMSTATE(RemovedMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing container_remove before deallocator",
                       "API Misuse")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportMissingRemove(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track container_remove calls: remember the object that was unlinked.
  if (knighter::callIsRole(Call, "container_remove")) {
    if (Call.getNumArgs() < 1)
      return;

    const Expr *Arg = Call.getArgExpr(0);
    if (!Arg)
      return;

    const MemRegion *MR = getMemRegionFromExpr(Arg, C);
    if (!MR)
      return;

    MR = MR->getBaseRegion();
    if (!MR)
      return;

    State = State->set<RemovedMap>(MR, true);
    C.addTransition(State);
    return;
  }

  // Detect deallocator calls inside container_insert that free an inserted
  // object parameter without a preceding container_remove call.
  if (!knighter::callIsRole(Call, "deallocator"))
    return;

  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || !knighter::declIsRole(FD, "container_insert"))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *Arg = Call.getArgExpr(0);
  if (!Arg)
    return;

  // The deallocator must directly use a parameter of the container_insert
  // function.  Use the raw Arg for getMemRegionFromExpr() as required.
  const Expr *E = Arg->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return;

  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD)
    return;

  const DeclContext *DC = PVD->getDeclContext();
  if (DC != FD)
    return;

  const MemRegion *MR = getMemRegionFromExpr(Arg, C);
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  const bool *Removed = State->get<RemovedMap>(MR);
  if (Removed && *Removed)
    return;

  reportMissingRemove(Call, C);
}

void SAGenTestChecker::reportMissingRemove(const CallEvent &Call,
                                           CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing container_remove before deallocator", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects deallocator calls in container_insert without a preceding container_remove",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "container_insert": {
    "names": ["xmlAddChild"],
    "description": "inserts an object into a container; the inserted object may already be linked in another container, so it must be unlinked before being freed"
  },
  "container_remove": {
    "names": ["xmlUnlinkNodeInternal"],
    "description": "removes or unlinks an object from its current container/list"
  },
  "deallocator": {
    "names": ["xmlFreeNode"],
    "description": "frees an object; after this call the object must not remain referenced by any container"
  }
}
*/
