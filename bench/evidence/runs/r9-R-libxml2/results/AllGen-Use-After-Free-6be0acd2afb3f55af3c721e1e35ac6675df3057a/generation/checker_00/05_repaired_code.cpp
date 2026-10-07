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
#include "clang/AST/DeclBase.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(UnlinkedRegions, const MemRegion *)

namespace {
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing container removal before free",
                       "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "container_remove"))
    return;

  if (Call.getNumArgs() < 1)
    return;

  SVal Arg0 = Call.getArgSVal(0);
  const MemRegion *R = Arg0.getAsRegion();
  if (!R)
    return;

  R = R->getBaseRegion();
  if (!R)
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<UnlinkedRegions>(R))
    return;

  State = State->add<UnlinkedRegions>(R);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "deallocator"))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || !knighter::declIsRole(FD, "container_insert"))
    return;

  // Ensure the freed argument is a parameter of the current function.
  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;

  ArgExpr = ArgExpr->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(ArgExpr);
  if (!DRE)
    return;

  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD)
    return;

  if (PVD->getDeclContext() != static_cast<const DeclContext *>(FD))
    return;

  // Get the memory region of the object being freed.
  SVal Arg0 = Call.getArgSVal(0);
  const MemRegion *R = Arg0.getAsRegion();
  if (!R)
    return;

  R = R->getBaseRegion();
  if (!R)
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<UnlinkedRegions>(R))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "deallocator called on possibly linked object; missing container_remove "
      "before free",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects deallocation of an object that may still be linked into its "
      "container without prior container removal",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "deallocator": {"names": ["xmlFreeNode"], "description": "frees an object; the object must no longer be reachable from any container afterward"},
  "container_remove": {"names": ["xmlUnlinkNodeInternal"], "description": "removes or unlinks an object from its parent/sibling structure before it is freed"},
  "container_insert": {"names": ["xmlAddChild"], "description": "inserts or links an object into a container, parent, or list"}
}
*/
