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
#include "clang/AST/Decl.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(RemovedRegions, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::BeginFunction, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing container_remove before deallocator",
                       "Memory Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();
  const Decl *D = LCtx->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || !knighter::declIsRole(FD, "container_insert"))
    return;

  for (const ParmVarDecl *PVD : FD->parameters()) {
    if (!PVD->getType()->isPointerType())
      continue;

    SVal LVal = State->getLValue(PVD, LCtx);
    const MemRegion *MR = LVal.getAsRegion();
    if (!MR)
      continue;

    State = State->set<RemovedRegions>(MR, false);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track explicit removals from containers.
  if (knighter::callIsRole(Call, "container_remove")) {
    for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
      SVal Arg = Call.getArgSVal(i);
      const MemRegion *MR = Arg.getAsRegion();
      if (!MR)
        continue;

      State = State->set<RemovedRegions>(MR, true);
    }
    C.addTransition(State);
    return;
  }

  // Check for deallocating an input object without prior removal.
  if (knighter::callIsRole(Call, "deallocator")) {
    const Decl *D = C.getLocationContext()->getDecl();
    const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
    if (!FD || !knighter::declIsRole(FD, "container_insert"))
      return;

    for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
      SVal Arg = Call.getArgSVal(i);
      const MemRegion *MR = Arg.getAsRegion();
      if (!MR)
        continue;

      // We only care about direct parameter regions of the container_insert
      // function.
      const VarRegion *VR = dyn_cast<VarRegion>(MR);
      if (!VR)
        continue;

      const VarDecl *VD = VR->getDecl();
      if (!VD)
        continue;

      const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(VD);
      if (!PVD || PVD->getDeclContext() != FD)
        continue;

      const bool *Removed = State->get<RemovedRegions>(MR);
      if (Removed && *Removed)
        continue;

      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Input object freed without container_remove", N);
      report->addRange(Call.getSourceRange());
      C.emitReport(std::move(report));
      return; // avoid duplicate warnings for the same call
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects deallocation of an input object without prior container_remove",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "container_insert": {"names": ["xmlAddChild"], "description": "function that inserts an object into a container"},
  "container_remove": {"names": ["xmlUnlinkNodeInternal"], "description": "function that unlinks/removes an object from its container"},
  "deallocator": {"names": ["xmlFreeNode"], "description": "function that frees/deallocates an object; the object must not be used afterwards"}
}
*/
