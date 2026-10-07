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

// Set of local variables that currently hold a value from an
// allocator/duplicator/null_on_failure and have not yet been inserted,
// deallocated, or returned.
REGISTER_SET_WITH_PROGRAMSTATE(CandidateSet, const MemRegion *)

namespace {
class SAGenTestChecker : public Checker<
    check::Bind,
    check::PreCall,
    check::PreStmt<ReturnStmt>,
    check::EndFunction
> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory Leak", "Memory Management")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  bool isOwnershipProducingCall(const CallExpr *CE) const;
  const MemRegion *getVarRegionFromDeclRef(const Expr *E, CheckerContext &C) const;
  void reportLeak(const MemRegion *MR, CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isOwnershipProducingCall(const CallExpr *CE) const {
  if (!CE)
    return false;

  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return false;

  return knighter::declIsRole(FD, "allocator") ||
         knighter::declIsRole(FD, "duplicator") ||
         knighter::declIsRole(FD, "null_on_failure");
}

const MemRegion *SAGenTestChecker::getVarRegionFromDeclRef(const Expr *E,
                                                           CheckerContext &C) const {
  if (!E)
    return nullptr;

  const Expr *E2 = E->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E2);
  if (!DRE)
    return nullptr;

  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return nullptr;

  const MemRegion *MR = C.getState()->getRegion(VD, C.getLocationContext());
  if (!MR)
    return nullptr;

  return MR->getBaseRegion();
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();

  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;

  const VarDecl *VD = VR->getDecl();
  if (!VD || !VD->isLocalVarDecl())
    return;

  const CallExpr *CE = nullptr;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      CE = dyn_cast<CallExpr>(RHS);
    }
  } else if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    if (VD->hasInit()) {
      const Expr *Init = VD->getInit()->IgnoreParenImpCasts();
      CE = dyn_cast<CallExpr>(Init);
    }
  }

  if (!CE)
    return;

  if (!isOwnershipProducingCall(CE))
    return;

  State = State->add<CandidateSet>(MR);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  bool Changed = false;

  if (knighter::callIsRole(Call, "container_insert") ||
      knighter::callIsRole(Call, "deallocator")) {
    for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
      const Expr *Arg = Call.getArgExpr(I);
      const MemRegion *MR = getVarRegionFromDeclRef(Arg, C);
      if (MR && State->contains<CandidateSet>(MR)) {
        State = State->remove<CandidateSet>(MR);
        Changed = true;
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS,
                                    CheckerContext &C) const {
  if (!RS)
    return;

  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  const MemRegion *MR = getVarRegionFromDeclRef(RetE, C);
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<CandidateSet>(MR)) {
    State = State->remove<CandidateSet>(MR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS,
                                        CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();

  for (const MemRegion *MR : State->get<CandidateSet>()) {
    if (!MR)
      continue;

    // Only report candidates that belong to the function that is ending.
    const VarRegion *VR = dyn_cast<VarRegion>(MR);
    if (!VR)
      continue;

    const VarDecl *VD = VR->getDecl();
    if (!VD)
      continue;

    const DeclContext *Parent = VD->getParentFunctionOrMethod();
    if (!Parent)
      continue;

    const auto *ParentFD = dyn_cast<FunctionDecl>(Parent);
    if (!ParentFD || ParentFD != LCtx->getDecl())
      continue;

    SVal Val = State->getSVal(MR);
    if (Val.isZeroConstant())
      continue;

    reportLeak(MR, C);
  }
}

void SAGenTestChecker::reportLeak(const MemRegion *MR,
                                  CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Memory leak: value from allocator/duplicator not inserted or deallocated",
      N);

  if (const VarRegion *VR = dyn_cast<VarRegion>(MR))
    Report->addRange(VR->getDecl()->getSourceRange());

  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memory leaks of values produced by allocator/duplicator "
      "functions that are not inserted or deallocated",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {"names": ["triggerStepAllocate"], "description": "allocates and returns a new object; may return NULL on failure"},
  "duplicator": {"names": ["sqlite3SrcListDup"], "description": "creates and returns a new copy of an object; may return NULL on failure"},
  "null_on_failure": {"names": ["triggerStepAllocate", "sqlite3SrcListDup"], "description": "function that may return NULL on failure"},
  "container_insert": {"names": ["sqlite3SrcListAppendList"], "description": "inserts/takes ownership of a value into a container"},
  "deallocator": {"names": ["sqlite3SrcListDelete"], "description": "frees memory or an object; the pointer must not be used afterwards"}
}
*/
