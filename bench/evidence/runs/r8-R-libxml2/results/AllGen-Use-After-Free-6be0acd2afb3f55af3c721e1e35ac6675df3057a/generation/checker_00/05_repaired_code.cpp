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

REGISTER_MAP_WITH_PROGRAMSTATE(NodeUnlinkState, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Node freed without unlinking",
                       "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C,
                 const MemRegion *R) const;
};

static bool isWrapper(CheckerContext &C) {
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return false;
  const Decl *D = LCtx->getDecl();
  if (const auto *FD = dyn_cast_or_null<FunctionDecl>(D))
    return knighter::declIsRole(FD, "wrapper");
  return false;
}

static const MemRegion *getNodeRegion(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

static const MemRegion *getNodeFromContentMerger(const CallEvent &Call,
                                                 CheckerContext &C) {
  for (unsigned I = 0, N = Call.getNumArgs(); I < N; ++I) {
    const Expr *Arg = Call.getArgExpr(I);
    if (!Arg)
      continue;
    const Expr *E = Arg->IgnoreParenImpCasts();
    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      return getNodeRegion(ME->getBase(), C);
    }
  }

  if (Call.getNumArgs() > 0)
    return getNodeRegion(Call.getArgExpr(0), C);
  return nullptr;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isWrapper(C))
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  if (knighter::callIsRole(Call, "content_merger")) {
    const MemRegion *R = getNodeFromContentMerger(Call, C);
    if (R) {
      const bool *UnlinkState = State->get<NodeUnlinkState>(R);
      if (!UnlinkState || *UnlinkState != false) {
        State = State->set<NodeUnlinkState>(R, true);
        Changed = true;
      }
    }
  }

  if (knighter::callIsRole(Call, "unlinker")) {
    if (Call.getNumArgs() > 0) {
      const MemRegion *R = getNodeRegion(Call.getArgExpr(0), C);
      if (R) {
        State = State->set<NodeUnlinkState>(R, false);
        Changed = true;
      }
    }
  }

  if (knighter::callIsRole(Call, "deallocator")) {
    if (Call.getNumArgs() > 0) {
      const MemRegion *R = getNodeRegion(Call.getArgExpr(0), C);
      if (R) {
        const bool *UnlinkState = State->get<NodeUnlinkState>(R);
        if (UnlinkState && *UnlinkState == true) {
          reportBug(Call, C, R);
        }
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::reportBug(const CallEvent &Call, CheckerContext &C,
                                 const MemRegion *R) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Node freed without unlinking from tree/list first", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing a linked node without unlinking it first",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "deallocator": {"names": ["xmlFreeNode"], "description": "Function that frees a node; if the node is still linked into a tree/list, it must be unlinked first."},
  "unlinker": {"names": ["xmlUnlinkNodeInternal"], "description": "Function that unlinks a node from its parent/children/prev/next links."},
  "content_merger": {"names": ["xmlTextAddContent"], "description": "Function that consumes/merges the content of a node before the node is freed."},
  "wrapper": {"names": ["xmlAddChild"], "description": "Wrapper function that merges content and frees a node; used to scope the pattern."}
}
*/
