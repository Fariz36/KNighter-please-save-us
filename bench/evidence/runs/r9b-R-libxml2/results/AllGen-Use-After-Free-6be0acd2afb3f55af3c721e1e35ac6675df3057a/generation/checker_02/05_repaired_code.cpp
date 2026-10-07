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
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks objects that have already been detached via a container_remove call.
REGISTER_SET_WITH_PROGRAMSTATE(UnlinkedRegions, const MemRegion *)

namespace {
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing container_remove before deallocator",
                       "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  const MemRegion *getFirstArgRegion(const CallEvent &Call,
                                     CheckerContext &C) const;
  bool isCurrentFunctionContainerInsert(CheckerContext &C) const;
};
} // end anonymous namespace

const MemRegion *
SAGenTestChecker::getFirstArgRegion(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (Call.getNumArgs() == 0)
    return nullptr;

  // First try to get the region directly from the argument's value.
  SVal ArgVal = Call.getArgSVal(0);
  if (const MemRegion *MR = ArgVal.getAsRegion())
    return MR;

  // Fallback: if the argument is a simple reference to a parameter, use the
  // region of the parameter variable itself. This is needed when the pointer
  // value is symbolic (e.g. it comes from a function parameter).
  const auto *CE = dyn_cast<CallExpr>(Call.getOriginExpr());
  if (!CE || CE->getNumArgs() == 0)
    return nullptr;

  const Expr *ArgExpr = CE->getArg(0);
  if (!ArgExpr)
    return nullptr;
  ArgExpr = ArgExpr->IgnoreParenCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(ArgExpr)) {
    if (const auto *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
      SVal Loc = C.getState()->getLValue(PVD, C.getLocationContext());
      return Loc.getAsRegion();
    }
  }
  return nullptr;
}

bool SAGenTestChecker::isCurrentFunctionContainerInsert(CheckerContext &C) const {
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return false;
  return knighter::declIsRole(FD, "container_insert");
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "container_remove"))
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = getFirstArgRegion(Call, C);
  if (!MR)
    return;

  State = State->add<UnlinkedRegions>(MR);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "deallocator"))
    return;

  if (!isCurrentFunctionContainerInsert(C))
    return;

  const MemRegion *MR = getFirstArgRegion(Call, C);
  if (!MR)
    return;

  // Verify that the region corresponds to a parameter of the current function.
  const auto *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;
  const auto *PVD = dyn_cast<ParmVarDecl>(VR->getDecl());
  if (!PVD)
    return;
  const auto *FD = dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD || PVD->getDeclContext() != FD)
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<UnlinkedRegions>(MR))
    return; // already unlinked, safe

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Deallocator called on possibly linked object without prior container_remove",
      N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

//===----------------------------------------------------------------------===//
// Checker registration
//===----------------------------------------------------------------------===//

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects deallocator calls on objects that may still be linked without prior container_remove",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "container_remove": {"names": ["xmlUnlinkNodeInternal"], "description": "Detaches an object from its container/parent links."},
  "deallocator": {"names": ["xmlFreeNode"], "description": "Frees an object; it must not remain linked or reachable afterwards."},
  "container_insert": {"names": ["xmlAddChild"], "description": "Inserts an object into a container/tree; the object may already be linked when passed."}
}
*/
