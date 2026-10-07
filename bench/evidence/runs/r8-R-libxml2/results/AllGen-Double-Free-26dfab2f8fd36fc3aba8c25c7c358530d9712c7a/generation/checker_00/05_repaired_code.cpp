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
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
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

REGISTER_MAP_WITH_PROGRAMSTATE(TransferredResourceMap, const MemRegion *, SymbolRef)

namespace {

static bool isOwnershipTakingCall(const CallEvent &Call) {
  return knighter::callIsRole(Call, "ownership_taking_callee");
}

static bool isResourceDeallocator(const CallEvent &Call) {
  return knighter::callIsRole(Call, "resource_deallocator");
}

static const MemRegion *getPointerVarRegion(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();

  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return nullptr;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return nullptr;

  SVal LVal = C.getState()->getLValue(VD, C.getLocationContext());
  const MemRegion *Region = LVal.getAsRegion();
  if (!Region)
    return nullptr;

  return Region->getBaseRegion();
}

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double Free", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isOwnershipTakingCall(Call))
    return;

  SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
  if (!RetSym)
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
    const Expr *ArgE = Call.getArgExpr(I);
    const MemRegion *Region = getPointerVarRegion(ArgE, C);
    if (!Region)
      continue;

    State = State->set<TransferredResourceMap>(Region, RetSym);
    Changed = true;
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isResourceDeallocator(Call))
    return;

  if (Call.getNumArgs() == 0)
    return;

  const Expr *ArgE = Call.getArgExpr(0);
  const MemRegion *Region = getPointerVarRegion(ArgE, C);
  if (!Region)
    return;

  ProgramStateRef State = C.getState();
  const SymbolRef *RetSymPtr = State->get<TransferredResourceMap>(Region);
  if (!RetSymPtr || !*RetSymPtr)
    return;

  ConditionTruthVal IsNull =
      State->getConstraintManager().isNull(State, *RetSymPtr);
  if (!IsNull.isConstrainedTrue())
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Double free: resource already freed by callee on failure", N);
  if (const Expr *Origin = Call.getOriginExpr())
    Report->addRange(Origin->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free when a resource is freed by an ownership-taking callee on failure and then by the caller",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "ownership_taking_callee": {"names": ["xmlNewIOInputStream"], "description": "callee that takes ownership of a resource argument; if it fails, it releases the resource and returns NULL"},
  "resource_deallocator": {"names": ["xmlFreeParserInputBuffer"], "description": "function that deallocates a resource; its first argument is the resource pointer"}
}
*/
