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

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(StrongRootMap, const MemRegion *, bool)

namespace {
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Potential Use-After-Free", "Memory Error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "ref_get"))
    return;

  ProgramStateRef State = C.getState();
  unsigned NumArgs = Call.getNumArgs();
  // Skip the first context argument (e.g., lua_State *L).
  for (unsigned i = 1; i < NumArgs; ++i) {
    SVal ArgVal = Call.getArgSVal(i);
    const MemRegion *MR = ArgVal.getAsRegion();
    if (!MR)
      continue;
    MR = MR->getBaseRegion();
    if (!MR)
      continue;
    State = State->set<StrongRootMap>(MR, true);
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "container_insert"))
    return;

  // For container_insert(L, container, ...), the container is the first
  // non-context pointer argument. In our case, it is argument index 1.
  if (Call.getNumArgs() < 2)
    return;

  SVal ContainerVal = Call.getArgSVal(1);
  const MemRegion *MR = ContainerVal.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Rooted = State->get<StrongRootMap>(MR);
  if (Rooted && *Rooted)
    return; // Object is strongly rooted, safe.

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential use-after-free: container insertion may trigger GC while object is not strongly rooted",
      N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potential use-after-free when a container insertion may trigger GC and the object is not strongly rooted",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "container_insert": {"names": ["luaH_finishset"], "description": "inserts/updates an element in a container and may allocate/rehash, potentially triggering garbage collection"},
  "ref_get": {"names": ["sethvalue2s"], "description": "acquires a strong root/reference to an object, keeping it alive across potentially collecting operations"}
}
*/
