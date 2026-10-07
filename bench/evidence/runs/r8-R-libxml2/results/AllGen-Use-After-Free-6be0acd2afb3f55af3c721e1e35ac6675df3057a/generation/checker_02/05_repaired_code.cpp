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

// A true entry means the object region's content has been merged by a
// content_merger inside an api_entry, so it must be unlinked before being freed.
REGISTER_MAP_WITH_PROGRAMSTATE(NeedsUnlinkMap, const MemRegion *, bool)

namespace {
class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Frees linked node without unlinking",
                       "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportFreedLinkedNode(const CallEvent &Call, CheckerContext &C) const;
};

static const MemRegion *getRegion(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();
  ProgramStateRef State = C.getState();
  SVal V = State->getSVal(E, C.getLocationContext());
  const MemRegion *MR = V.getAsRegion();
  if (!MR)
    return nullptr;

  return MR->getBaseRegion();
}

static const MemRegion *
getLinkedObjectRegionFromMemberArg(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();
  const auto *ME = dyn_cast<MemberExpr>(E);
  if (!ME)
    return nullptr;

  return getRegion(ME->getBase(), C);
}

static bool isInApiEntry(CheckerContext &C) {
  const LocationContext *LC = C.getLocationContext();
  if (!LC)
    return false;

  const Decl *D = LC->getDecl();
  const auto *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return false;

  return knighter::declIsRole(FD, "api_entry");
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (knighter::callIsRole(Call, "content_merger")) {
    if (!isInApiEntry(C))
      return;

    bool Changed = false;
    for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
      const Expr *Arg = Call.getArgExpr(I);
      const MemRegion *Region = getLinkedObjectRegionFromMemberArg(Arg, C);
      if (Region) {
        State = State->set<NeedsUnlinkMap>(Region, true);
        Changed = true;
      }
    }

    if (Changed)
      C.addTransition(State);
    return;
  }

  if (knighter::callIsRole(Call, "unlinker")) {
    if (Call.getNumArgs() == 0)
      return;

    const Expr *Arg = Call.getArgExpr(0);
    const MemRegion *Region = getRegion(Arg, C);
    if (Region) {
      State = State->remove<NeedsUnlinkMap>(Region);
      C.addTransition(State);
    }
    return;
  }

  if (knighter::callIsRole(Call, "deallocator")) {
    if (Call.getNumArgs() == 0)
      return;

    const Expr *Arg = Call.getArgExpr(0);
    const MemRegion *Region = getRegion(Arg, C);
    if (!Region)
      return;

    const bool *NeedsUnlink = State->get<NeedsUnlinkMap>(Region);
    if (NeedsUnlink && *NeedsUnlink) {
      reportFreedLinkedNode(Call, C);
      State = State->remove<NeedsUnlinkMap>(Region);
      C.addTransition(State);
    }
    return;
  }
}

void SAGenTestChecker::reportFreedLinkedNode(const CallEvent &Call,
                                             CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "frees linked node without unlinking", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing a node that may still be linked without unlinking it first",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "api_entry": {"names": ["xmlAddChild"], "description": "entry API function that adds or links a node into a tree/list and may free a merged node"},
  "content_merger": {"names": ["xmlTextAddContent"], "description": "function that merges content from one object into another, after which the source object may still be linked"},
  "deallocator": {"names": ["xmlFreeNode"], "description": "function that frees a node object"},
  "unlinker": {"names": ["xmlUnlinkNodeInternal"], "description": "function that removes a node from its parent/sibling/child links before freeing"}
}
*/
