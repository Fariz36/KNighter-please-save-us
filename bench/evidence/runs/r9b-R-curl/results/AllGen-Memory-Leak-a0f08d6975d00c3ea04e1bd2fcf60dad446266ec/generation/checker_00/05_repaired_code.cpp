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
#include "llvm/Support/Casting.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map to track regions that have been zeroed/reset.
REGISTER_MAP_WITH_PROGRAMSTATE(ZeroedObjects, const MemRegion *, bool)

namespace {

// Helper: mark a region as zeroed.
static ProgramStateRef markZeroed(ProgramStateRef State, const MemRegion *Reg) {
  if (!Reg)
    return State;
  return State->set<ZeroedObjects>(Reg, true);
}

// Helper: check if a region (or its base) is marked zeroed.
static bool isZeroed(ProgramStateRef State, const MemRegion *Reg) {
  if (!Reg)
    return false;
  const bool *Zeroed = State->get<ZeroedObjects>(Reg);
  if (Zeroed && *Zeroed)
    return true;
  const MemRegion *Base = Reg->getBaseRegion();
  if (Base != Reg) {
    Zeroed = State->get<ZeroedObjects>(Base);
    if (Zeroed && *Zeroed)
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Resource Leak", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // If this call is an init or cleanup operation, mark the object as reset/zeroed.
  if (knighter::callIsRole(Call, "init") ||
      knighter::callIsRole(Call, "cleanup")) {
    if (Call.getNumArgs() < 1)
      return;

    SVal Arg = Call.getArgSVal(0);
    const MemRegion *Reg = Arg.getAsRegion();
    if (Reg) {
      State = markZeroed(State, Reg);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // If this is a container_remove call, check if the object was already zeroed.
  if (knighter::callIsRole(Call, "container_remove")) {
    if (Call.getNumArgs() < 1)
      return;

    SVal Arg = Call.getArgSVal(0);
    const MemRegion *Reg = Arg.getAsRegion();
    if (!Reg)
      return;

    // We only care when the argument is an embedded member (field).
    if (!isa<FieldRegion>(Reg))
      return;

    ProgramStateRef State = C.getState();
    if (isZeroed(State, Reg)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "container_remove on embedded member after containing object was "
          "reset; resource leak.",
          N);
      Report->addRange(Call.getSourceRange());
      C.emitReport(std::move(Report));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects resource leaks when a container_remove is performed after the "
      "containing object has been reset/zeroed",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "container_remove": {
    "names": ["Curl_peer_unlink"],
    "description": "Removes/unlinks an embedded member from its container; must be executed before the containing object's state is reset or zeroed, otherwise the link is lost and the resource leaks."
  },
  "init": {
    "names": ["memset"],
    "description": "Initializes or resets an object's memory, typically zeroing it; this invalidates any embedded link/ownership fields."
  },
  "cleanup": {
    "names": ["cf_h2_proxy_ctx_clear"],
    "description": "Cleans up and resets a containing object, often zeroing its fields; embedded links must be removed before this call."
  },
  "deallocator": {
    "names": ["curlx_free"],
    "description": "Frees allocated memory or an object; the pointer must not be used afterwards."
  }
}
*/
