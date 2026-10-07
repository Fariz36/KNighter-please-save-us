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

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Track memory regions that are currently only weakly referenced.
REGISTER_SET_WITH_PROGRAMSTATE(WeakRegions, const MemRegion *)

namespace {
class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall, check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use-after-free", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;

private:
  void reportWeakUse(const CallEvent &Call, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "weak_ref_get"))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  const MemRegion *MR = Ret.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  State = State->add<WeakRegions>(MR);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // A rooting/strong reference is acquired.
  if (knighter::callIsRole(Call, "ref_get")) {
    bool Changed = false;
    for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
      SVal Arg = Call.getArgSVal(I);
      const MemRegion *MR = Arg.getAsRegion();
      if (!MR)
        continue;

      MR = MR->getBaseRegion();
      if (!MR)
        continue;

      if (State->contains<WeakRegions>(MR)) {
        State = State->remove<WeakRegions>(MR);
        Changed = true;
      }
    }
    if (Changed)
      C.addTransition(State);
    return;
  }

  // A container/table mutation that may trigger an emergency GC.
  if (knighter::callIsRole(Call, "container_insert")) {
    for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
      SVal Arg = Call.getArgSVal(I);
      const MemRegion *MR = Arg.getAsRegion();
      if (!MR)
        continue;

      MR = MR->getBaseRegion();
      if (!MR)
        continue;

      if (State->contains<WeakRegions>(MR)) {
        reportWeakUse(Call, C);
        return;
      }
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;

  ProgramStateRef State = C.getState();

  const MemRegion *BaseR = Loc.getAsRegion();
  if (!BaseR)
    return;

  BaseR = BaseR->getBaseRegion();
  if (!BaseR)
    return;

  if (!State->contains<WeakRegions>(BaseR))
    return;

  // Propagate the "weak" mark to the object loaded from this region.
  SVal LoadedVal = State->getSVal(S, C.getLocationContext());
  const MemRegion *LoadedMR = LoadedVal.getAsRegion();
  if (!LoadedMR)
    return;

  LoadedMR = LoadedMR->getBaseRegion();
  if (!LoadedMR)
    return;

  State = State->add<WeakRegions>(LoadedMR);
  C.addTransition(State);
}

void SAGenTestChecker::reportWeakUse(const CallEvent &Call,
                                     CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Use-after-free: weakly referenced object used in container_insert "
      "without rooting.",
      N);

  if (const Expr *E = Call.getOriginExpr())
    Report->addRange(E->getSourceRange());

  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free of weakly referenced objects used in container "
      "insertions without rooting",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "weak_ref_get": {
    "names": ["fasttm", "luaT_gettmbyobj"],
    "description": "retrieves a value through a weak reference; the returned object may be collected by an emergency GC if not rooted"
  },
  "container_insert": {
    "names": ["luaH_finishset"],
    "description": "mutates a container/table and may allocate memory, potentially triggering an emergency garbage collection"
  },
  "ref_get": {
    "names": ["sethvalue2s"],
    "description": "stores an object into a strongly reachable location (e.g., the Lua stack), preventing its collection"
  }
}
*/
