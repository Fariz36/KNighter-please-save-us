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

REGISTER_SET_WITH_PROGRAMSTATE(WeakSymbols, SymbolRef)
REGISTER_SET_WITH_PROGRAMSTATE(WeakRegions, const MemRegion *)

namespace {

static ProgramStateRef markWeak(ProgramStateRef State, SVal V) {
  if (SymbolRef Sym = V.getAsSymbol()) {
    State = State->add<WeakSymbols>(Sym);
  }
  if (const MemRegion *R = V.getAsRegion()) {
    const MemRegion *Base = R->getBaseRegion();
    if (Base)
      State = State->add<WeakRegions>(Base);
  }
  return State;
}

static bool isWeak(ProgramStateRef State, SVal V) {
  if (SymbolRef Sym = V.getAsSymbol()) {
    if (State->contains<WeakSymbols>(Sym))
      return true;
  }
  if (const MemRegion *R = V.getAsRegion()) {
    const MemRegion *Base = R->getBaseRegion();
    if (Base && State->contains<WeakRegions>(Base))
      return true;
  }
  return false;
}

static ProgramStateRef unmarkWeak(ProgramStateRef State, SVal V) {
  if (SymbolRef Sym = V.getAsSymbol()) {
    State = State->remove<WeakSymbols>(Sym);
  }
  if (const MemRegion *R = V.getAsRegion()) {
    const MemRegion *Base = R->getBaseRegion();
    if (Base)
      State = State->remove<WeakRegions>(Base);
  }
  return State;
}

class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall, check::Location,
                     check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Weak reference use after GC",
                       "Garbage Collection")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "weak_lookup"))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  State = markWeak(State, Ret);
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;

  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  const MemRegion *Base = R->getBaseRegion();
  if (!Base)
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<WeakRegions>(Base))
    return;

  SVal Loaded = State->getSVal(S, C.getLocationContext());
  State = markWeak(State, Loaded);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!isWeak(State, Val))
    return;

  State = markWeak(State, Loc);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (knighter::callIsRole(Call, "ref_get")) {
    for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
      SVal Arg = Call.getArgSVal(I);
      State = unmarkWeak(State, Arg);
    }
    C.addTransition(State);
    return;
  }

  if (knighter::callIsRole(Call, "gc_trigger")) {
    for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
      SVal Arg = Call.getArgSVal(I);
      if (!isWeak(State, Arg))
        continue;

      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "Weakly referenced object passed to GC-triggering call without "
          "anchoring",
          N);
      Report->addRange(Call.getSourceRange());
      C.emitReport(std::move(Report));
      return;
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of weakly referenced GC objects across GC-triggering calls",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "weak_lookup": {
    "names": ["fasttm", "luaT_gettmbyobj"],
    "description": "Returns a pointer to a value that is only weakly referenced (e.g., from a weak table); the returned pointer does not keep the object alive."
  },
  "gc_trigger": {
    "names": ["luaH_finishset"],
    "description": "Function call that may allocate memory and trigger a garbage collection; any weakly referenced object passed to it must be anchored beforehand."
  },
  "ref_get": {
    "names": ["sethvalue2s"],
    "description": "Anchors/roots a GC object so it will not be collected; after this call the object is strongly referenced."
  }
}
*/
