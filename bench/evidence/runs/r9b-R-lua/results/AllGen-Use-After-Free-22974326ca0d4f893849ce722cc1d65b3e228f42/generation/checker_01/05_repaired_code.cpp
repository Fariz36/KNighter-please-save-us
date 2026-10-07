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
#include "knighter/roles.h"

#include <memory>
#include <utility>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(WeakRegionMap, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion *, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall,
                                       check::Location, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Weak reference use-after-free",
                       "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                 CheckerContext &C) const;

private:
  void reportWeakUseAfterFree(const CallEvent &Call, CheckerContext &C,
                              const MemRegion *MR) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Mark values returned by a weak/non-owning lookup as weak and unanchored.
  if (knighter::callIsRole(Call, "weak_lookup")) {
    const MemRegion *MR = Call.getReturnValue().getAsRegion();
    if (MR) {
      MR = MR->getBaseRegion();
      State = State->set<WeakRegionMap>(MR, true);
    }
  }

  // Mark objects stored into a GC-visible root as anchored.
  if (knighter::callIsRole(Call, "ref_get")) {
    for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
      SVal Arg = Call.getArgSVal(I);
      if (const MemRegion *MR = Arg.getAsRegion()) {
        MR = MR->getBaseRegion();

        const bool *Weak = State->get<WeakRegionMap>(MR);
        if (Weak && *Weak) {
          State = State->set<WeakRegionMap>(MR, false);
        }

        if (const MemRegion *const *AliasPtr =
                State->get<PtrAliasMap>(MR)) {
          const MemRegion *Alias = *AliasPtr;
          const bool *AliasWeak = State->get<WeakRegionMap>(Alias);
          if (AliasWeak && *AliasWeak) {
            State = State->set<WeakRegionMap>(Alias, false);
          }
        }
      }
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "allocator"))
    return;

  ProgramStateRef State = C.getState();

  // If an allocator / collection-triggering call receives a weakly referenced
  // object that is still unanchored, the object may be reclaimed during the
  // call and then used afterwards.
  for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
    SVal Arg = Call.getArgSVal(I);
    const MemRegion *MR = Arg.getAsRegion();
    if (!MR)
      continue;

    MR = MR->getBaseRegion();
    const bool *Weak = State->get<WeakRegionMap>(MR);
    if (Weak && *Weak) {
      reportWeakUseAfterFree(Call, C, MR);
      return;
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;

  ProgramStateRef State = C.getState();

  const MemRegion *LocMR = Loc.getAsRegion();
  if (!LocMR)
    return;
  LocMR = LocMR->getBaseRegion();

  const bool *Weak = State->get<WeakRegionMap>(LocMR);
  if (!Weak || !*Weak)
    return;

  // Loading from a weak slot yields a weakly referenced object.
  const Expr *E = dyn_cast<Expr>(S);
  if (!E)
    return;

  const MemRegion *LoadedMR = getMemRegionFromExpr(E, C);
  if (!LoadedMR)
    return;
  LoadedMR = LoadedMR->getBaseRegion();

  State = State->set<WeakRegionMap>(LoadedMR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHS = Loc.getAsRegion();
  if (!LHS)
    return;
  LHS = LHS->getBaseRegion();

  const MemRegion *RHS = Val.getAsRegion();
  if (!RHS)
    return;
  RHS = RHS->getBaseRegion();

  // Propagate weak/unanchored status through simple pointer assignments.
  const bool *Weak = State->get<WeakRegionMap>(RHS);
  if (Weak && *Weak) {
    State = State->set<WeakRegionMap>(LHS, true);
  }

  // Track simple aliasing so anchoring one alias can anchor the other.
  State = State->set<PtrAliasMap>(LHS, RHS);
  State = State->set<PtrAliasMap>(RHS, LHS);

  C.addTransition(State);
}

void SAGenTestChecker::reportWeakUseAfterFree(const CallEvent &Call,
                                              CheckerContext &C,
                                              const MemRegion *MR) const {
  (void)MR;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Weakly referenced object not anchored before allocation; possible "
      "use-after-free",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free of weakly referenced objects when passed to an "
      "allocation-triggering call without anchoring",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "weak_lookup": {"names": ["fasttm"], "description": "lookup that may return a non-owning/weak reference to an object; the object may be collected unless anchored"},
  "allocator": {"names": ["luaH_finishset"], "description": "call that may allocate memory and trigger emergency garbage collection; weakly referenced objects passed to it must be anchored beforehand"},
  "ref_get": {"names": ["sethvalue2s"], "description": "stores an object pointer into a GC-visible root, making it strongly reachable/anchored"}
}
*/
