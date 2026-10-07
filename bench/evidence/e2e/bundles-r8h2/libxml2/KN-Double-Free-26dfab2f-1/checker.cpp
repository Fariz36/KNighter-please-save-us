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

REGISTER_SET_WITH_PROGRAMSTATE(ConsumedResources, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double free", "Memory error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "ownership_consumer_frees_on_failure"))
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    const Expr *Arg = Call.getArgExpr(I);
    if (!Arg)
      continue;

    Arg = Arg->IgnoreImpCasts();

    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Arg);
    if (!DRE)
      continue;

    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      continue;

    if (!knighter::isRole("resource", VD->getName()))
      continue;

    SVal ArgVal = Call.getArgSVal(I);
    const MemRegion *MR = ArgVal.getAsRegion();
    if (!MR)
      continue;

    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    if (!State->contains<ConsumedResources>(MR)) {
      State = State->add<ConsumedResources>(MR);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "deallocator"))
    return;

  if (Call.getNumArgs() == 0)
    return;

  SVal ArgVal = Call.getArgSVal(0);
  const MemRegion *MR = ArgVal.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<ConsumedResources>(MR))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Double free: resource already consumed by ownership consumer.", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free when a resource passed to an ownership consumer is "
      "freed again",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "resource": {"names": ["input"], "description": "an owned resource pointer that may be consumed by a function"},
  "ownership_consumer_frees_on_failure": {"names": ["xmlNewIOInputStream"], "description": "function that takes ownership of a resource and releases it on failure"},
  "deallocator": {"names": ["xmlFreeParserInputBuffer"], "description": "function that releases/frees a resource"},
  "null_on_failure": {"names": ["xmlNewIOInputStream"], "description": "function that returns NULL on failure"},
  "duplicate_cleanup": {"names": ["xmlFreeParserInputBuffer"], "description": "cleanup action that duplicates a release already performed by the callee"},
  "context_cleanup": {"names": ["xmlFreeParserCtxt"], "description": "cleanup action that releases a context whose ownership remains with the caller"}
}
*/
