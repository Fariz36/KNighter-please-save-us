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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map: base MemRegion -> true if the object has been reset/cleaned.
REGISTER_MAP_WITH_PROGRAMSTATE(ResetObjectMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Link Detach After Reset", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

/// \brief Return the base region of the I-th argument if it is a pointer to a
///        memory region, otherwise nullptr.
static const MemRegion *getBaseRegionFromCallArg(const CallEvent &Call,
                                                 unsigned I) {
  if (I >= Call.getNumArgs())
    return nullptr;
  const MemRegion *R = Call.getArgSVal(I).getAsRegion();
  return R ? R->getBaseRegion() : nullptr;
}

/// \brief Check whether the given region is a field that plays the
///        "link_storage" role.
static bool isLinkStorageRegion(const MemRegion *R) {
  if (const auto *FR = dyn_cast<FieldRegion>(R)) {
    return knighter::declIsRole(FR->getDecl(), "link_storage");
  }
  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  // Remember that an object has been reset or cleaned.
  if (knighter::callIsRole(Call, "state_reset") ||
      knighter::callIsRole(Call, "cleanup")) {
    const MemRegion *Base = getBaseRegionFromCallArg(Call, 0);
    if (!Base)
      return;
    ProgramStateRef State = C.getState();
    State = State->set<ResetObjectMap>(Base, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Detect link_detach on a link-storage field of an already-reset object.
  if (!knighter::callIsRole(Call, "link_detach"))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const MemRegion *R = Call.getArgSVal(i).getAsRegion();
    if (!R)
      continue;
    if (isLinkStorageRegion(R)) {
      const MemRegion *Base = R->getBaseRegion();
      if (Base) {
        const bool *Reset = State->get<ResetObjectMap>(Base);
        if (Reset && *Reset) {
          // Report the bug.
          if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
            auto report = std::make_unique<PathSensitiveBugReport>(
                *BT,
                "link_detach called after object state reset; link metadata "
                "already cleared",
                N);
            report->addRange(Call.getSourceRange());
            C.emitReport(std::move(report));
          }
          return; // Report only once.
        }
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects link_detach calls after object state has been reset, which may "
      "leak link metadata",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "cleanup": {
    "names": ["cf_h2_proxy_ctx_clear"],
    "description": "function that clears/resets the state of its object; after it returns, the object's link metadata may be zeroed/cleared"
  },
  "destructor": {
    "names": ["cf_h2_proxy_ctx_free"],
    "description": "function that destroys/frees an object; may call cleanup and link_detach"
  },
  "state_reset": {
    "names": ["memset"],
    "description": "operation that zeroes/resets the memory of its first argument, clearing fields including link storage"
  },
  "link_detach": {
    "names": ["Curl_peer_unlink"],
    "description": "operation that detaches/unlinks a link/peer entry from its container; must run before the container's link storage is cleared"
  },
  "link_storage": {
    "names": ["dest"],
    "description": "field inside the container that stores the link/peer metadata used by link_detach"
  }
}
*/
