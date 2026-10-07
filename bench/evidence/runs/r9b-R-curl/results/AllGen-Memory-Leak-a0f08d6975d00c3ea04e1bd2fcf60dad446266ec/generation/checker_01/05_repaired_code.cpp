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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(ClearedRegionMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Resource Leak", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportLeak(const CallEvent &Call, CheckerContext &C) const;
};

static const MemRegion *getPointeeRegion(SVal V, CheckerContext &C) {
  if (const MemRegion *R = V.getAsRegion())
    return R;

  if (SymbolRef Sym = V.getAsLocSymbol()) {
    return C.getSValBuilder().getRegionManager().getSymbolicRegion(Sym);
  }

  return nullptr;
}

static bool isRegionCleared(ProgramStateRef State, const MemRegion *R) {
  while (R) {
    const bool *Cleared = State->get<ClearedRegionMap>(R);
    if (Cleared && *Cleared)
      return true;
    if (const auto *SR = dyn_cast<SubRegion>(R))
      R = SR->getSuperRegion();
    else
      break;
  }
  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "cleanup"))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const MemRegion *R = getPointeeRegion(Call.getArgSVal(0), C);
  if (!R)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<ClearedRegionMap>(R, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "container_remove"))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const MemRegion *R = getPointeeRegion(Call.getArgSVal(0), C);
  if (!R)
    return;

  if (!isRegionCleared(C.getState(), R))
    return;

  reportLeak(Call, C);
}

void SAGenTestChecker::reportLeak(const CallEvent &Call,
                                  CheckerContext &C) const {
  if (!BT)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "container_remove called after cleanup reset the containing object; "
      "link state is already cleared and the resource may leak",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects resource leaks from container removal after cleanup reset the container",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "cleanup": {"names": ["cf_h2_proxy_ctx_clear"], "description": "resets/clears an object, invalidating its internal state (e.g., zeroing memory)."},
  "container_remove": {"names": ["Curl_peer_unlink"], "description": "unlinks/removes an element from a container/list; the first pointer argument points to the link/node embedded in a containing object."},
  "deallocator": {"names": ["curlx_free"], "description": "frees allocated memory/object; pointer must not be used afterwards."}
}
*/
