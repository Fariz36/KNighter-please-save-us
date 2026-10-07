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

// Map tracking pointer regions that were obtained from a ref_get call and
// have not yet been anchored by a container_insert call.
REGISTER_MAP_WITH_PROGRAMSTATE(BorrowedRefMap, const MemRegion *, bool)

namespace {

// Helper: mark a pointer value as borrowed (unrooted).
ProgramStateRef markBorrowed(ProgramStateRef State, SVal Val) {
  if (!Val.getAs<Loc>())
    return State;
  const MemRegion *MR = Val.getAsRegion();
  if (!MR)
    return State;
  MR = MR->getBaseRegion();
  return State->set<BorrowedRefMap>(MR, true);
}

// Helper: check if a pointer value is borrowed.
bool isBorrowed(ProgramStateRef State, SVal Val) {
  if (!Val.getAs<Loc>())
    return false;
  const MemRegion *MR = Val.getAsRegion();
  if (!MR)
    return false;
  if (const bool *B = State->get<BorrowedRefMap>(MR)) {
    if (*B) return true;
  }
  MR = MR->getBaseRegion();
  if (const bool *B = State->get<BorrowedRefMap>(MR)) {
    if (*B) return true;
  }
  return false;
}

// Helper: mark a pointer value as rooted (no longer borrowed).
ProgramStateRef markRooted(ProgramStateRef State, SVal Val) {
  if (!Val.getAs<Loc>())
    return State;
  const MemRegion *MR = Val.getAsRegion();
  if (!MR)
    return State;
  MR = MR->getBaseRegion();
  return State->remove<BorrowedRefMap>(MR);
}

class SAGenTestChecker : public Checker<check::PostCall, check::Bind,
                                         check::Location, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use-after-free",
                       "Borrowed reference used across GC-triggering call")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "ref_get"))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  ProgramStateRef NewState = markBorrowed(State, Ret);
  if (NewState != State)
    C.addTransition(NewState);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (isBorrowed(State, Val)) {
    ProgramStateRef NewState = markBorrowed(State, Loc);
    if (NewState != State)
      C.addTransition(NewState);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  const bool *B = State->get<BorrowedRefMap>(MR);
  if (B && *B) {
    SVal Result = State->getSVal(S, C.getLocationContext());
    ProgramStateRef NewState = markBorrowed(State, Result);
    if (NewState != State)
      C.addTransition(NewState);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (knighter::callIsRole(Call, "container_insert")) {
    bool Changed = false;
    for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
      SVal Arg = Call.getArgSVal(i);
      ProgramStateRef NewState = markRooted(State, Arg);
      if (NewState != State) {
        State = NewState;
        Changed = true;
      }
    }
    if (Changed)
      C.addTransition(State);
    return;
  }

  if (knighter::callIsRole(Call, "cleanup")) {
    for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
      SVal Arg = Call.getArgSVal(i);
      if (isBorrowed(State, Arg)) {
        reportBug(Call, C);
        break; // one report per call
      }
    }
  }
}

void SAGenTestChecker::reportBug(const CallEvent &Call,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Use-after-free: borrowed reference from weak container used across "
      "GC-triggering call without anchoring",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use-after-free of borrowed references across GC-triggering calls",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "ref_get": {
    "names": ["fasttm", "gfasttm", "luaT_gettmbyobj"],
    "description": "Obtains a reference to an object that may be only weakly referenced (e.g., from a weak table/metatable) without making it strongly reachable."
  },
  "cleanup": {
    "names": ["luaH_finishset"],
    "description": "Performs a memory management or garbage collection operation that can trigger an emergency collection and reclaim weakly referenced objects."
  },
  "container_insert": {
    "names": ["sethvalue2s"],
    "description": "Inserts/roots an object into a strong container (e.g., a stack), making it reachable during subsequent operations."
  }
}
*/
