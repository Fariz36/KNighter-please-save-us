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

// Tracks objects whose cleanup/reset routine has already run.
// The key is the object's base MemRegion.
REGISTER_MAP_WITH_PROGRAMSTATE(CleanedRegions, const MemRegion *, bool)

namespace {

static const MemRegion *getBaseRegionFromArg(const CallEvent &Call,
                                             unsigned Idx,
                                             CheckerContext &C) {
  if (Idx >= Call.getNumArgs())
    return nullptr;

  const Expr *Arg = Call.getArgExpr(Idx);
  if (!Arg)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(Arg, C);
  if (!MR)
    return nullptr;

  return MR->getBaseRegion();
}

class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Container Remove After Cleanup",
                       "Memory leak")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportLeak(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (knighter::callIsRole(Call, "cleanup")) {
    for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
      const MemRegion *Base = getBaseRegionFromArg(Call, I, C);
      if (Base) {
        State = State->set<CleanedRegions>(Base, true);
        C.addTransition(State);
        return;
      }
    }
    return;
  }

  if (knighter::callIsRole(Call, "deallocator")) {
    for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
      const MemRegion *Base = getBaseRegionFromArg(Call, I, C);
      if (Base) {
        State = State->remove<CleanedRegions>(Base);
        C.addTransition(State);
        return;
      }
    }
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "container_remove"))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    const MemRegion *Base = getBaseRegionFromArg(Call, I, C);
    if (!Base)
      continue;

    const bool *Cleaned = State->get<CleanedRegions>(Base);
    if (Cleaned && *Cleaned) {
      reportLeak(Call, C);
      return;
    }
  }
}

void SAGenTestChecker::reportLeak(const CallEvent &Call,
                                  CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "container_remove after cleanup; link node was zeroed and may leak",
      N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects container_remove on an embedded link node after its containing "
      "object has already been cleanup/reset/zeroed",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "cleanup": {
    "names": ["cf_h2_proxy_ctx_clear"],
    "description": "clears/resets an object, typically zeroing or invalidating its contents"
  },
  "container_remove": {
    "names": ["Curl_peer_unlink"],
    "description": "unlinks/removes an embedded link node from its containing object or container"
  },
  "deallocator": {
    "names": ["curlx_free"],
    "description": "frees memory or an object; the pointer must not be used afterwards"
  }
}
*/
