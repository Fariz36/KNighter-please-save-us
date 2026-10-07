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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "knighter/roles.h"

#include <memory>
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(AllocatedRegions, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(FreedRegions, const MemRegion *, bool)

namespace {
class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory Leak", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                 CheckerContext &C) const;

private:
  const MemRegion *getRegion(SVal V) const;
  void reportLeak(const Stmt *S, CheckerContext &C) const;
};

const MemRegion *SAGenTestChecker::getRegion(SVal V) const {
  return V.getAsRegion();
}

void SAGenTestChecker::reportLeak(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential memory leak: overwriting owned pointer without freeing "
      "previous value",
      N);
  if (S)
    report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "allocator"))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  const MemRegion *Region = getRegion(Ret);
  if (!Region)
    return;

  Region = Region->getBaseRegion();
  if (!Region)
    return;

  State = State->set<AllocatedRegions>(Region, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "deallocator") &&
      !knighter::callIsRole(Call, "ref_put"))
    return;

  if (Call.getNumArgs() == 0)
    return;

  ProgramStateRef State = C.getState();
  SVal Ptr = Call.getArgSVal(0);
  const MemRegion *Region = getRegion(Ptr);
  if (!Region)
    return;

  Region = Region->getBaseRegion();
  if (!Region)
    return;

  State = State->remove<AllocatedRegions>(Region);
  State = State->set<FreedRegions>(Region, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *ValR = getRegion(Val);
  if (!ValR)
    return;

  ValR = ValR->getBaseRegion();
  if (!ValR)
    return;

  const bool *Allocated = State->get<AllocatedRegions>(ValR);
  if (!Allocated || !*Allocated)
    return;

  const MemRegion *LocR = Loc.getAsRegion();
  if (!LocR)
    return;

  if (!isa<FieldRegion>(LocR))
    return;

  SVal OldVal = State->getSVal(LocR);
  if (State->isNull(OldVal).isConstrainedTrue())
    return;

  const MemRegion *OldR = getRegion(OldVal);
  if (OldR) {
    OldR = OldR->getBaseRegion();
    if (OldR) {
      const bool *Freed = State->get<FreedRegions>(OldR);
      if (Freed && *Freed)
        return;
      if (OldR == ValR)
        return;
    }
  }

  reportLeak(StoreE, C);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memory leaks when overwriting an owned pointer without freeing "
      "the previous value",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {"names": ["xmlMalloc"], "description": "allocates memory and returns a pointer to it, which the caller owns and must later release"},
  "deallocator": {"names": ["xmlFree"], "description": "frees dynamically allocated memory; the pointer must not be used afterwards"},
  "ref_put": {"names": [], "description": "decrements a reference count and may free the object when it reaches zero"}
}
*/
