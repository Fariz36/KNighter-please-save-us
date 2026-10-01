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

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks SrcList memory regions that are currently owned by the target function.
REGISTER_MAP_WITH_PROGRAMSTATE(OwnedSrcListMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<
    check::BeginFunction,
    check::PostCall,
    check::PreCall,
    check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory leak", "Memory Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  static bool isTargetFunction(CheckerContext &C);
  static bool isSrcListAllocator(const CallEvent &Call, CheckerContext &C);
  static bool isSrcListConsumer(const CallEvent &Call, CheckerContext &C);
  static ProgramStateRef addOwned(ProgramStateRef State, const MemRegion *MR);
  static ProgramStateRef removeOwned(ProgramStateRef State, const MemRegion *MR);
};

bool SAGenTestChecker::isTargetFunction(CheckerContext &C) {
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  return FD && FD->getNameAsString() == "sqlite3TriggerUpdateStep";
}

bool SAGenTestChecker::isSrcListAllocator(const CallEvent &Call,
                                          CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, "sqlite3SrcListDup", C) ||
         ExprHasName(E, "sqlite3SrcListAppendFromTerm", C);
}

bool SAGenTestChecker::isSrcListConsumer(const CallEvent &Call,
                                         CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, "sqlite3SrcListDelete", C) ||
         ExprHasName(E, "sqlite3SrcListAppendList", C) ||
         ExprHasName(E, "sqlite3SelectNew", C);
}

ProgramStateRef SAGenTestChecker::addOwned(ProgramStateRef State,
                                           const MemRegion *MR) {
  if (!MR)
    return State;
  MR = MR->getBaseRegion();
  if (!MR)
    return State;
  return State->set<OwnedSrcListMap>(MR, true);
}

ProgramStateRef SAGenTestChecker::removeOwned(ProgramStateRef State,
                                              const MemRegion *MR) {
  if (!MR)
    return State;
  MR = MR->getBaseRegion();
  if (!MR)
    return State;
  return State->remove<OwnedSrcListMap>(MR);
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  if (!isTargetFunction(C))
    return;

  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();
  const Decl *D = LCtx->getDecl();
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  for (const ParmVarDecl *PVD : FD->parameters()) {
    if (PVD->getNameAsString() == "pFrom") {
      SVal Val = State->getSVal(State->getRegion(PVD, LCtx));
      if (const MemRegion *MR = Val.getAsRegion()) {
        State = addOwned(State, MR);
      }
      break;
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isTargetFunction(C))
    return;

  if (!isSrcListAllocator(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  if (const MemRegion *MR = RetVal.getAsRegion()) {
    State = addOwned(State, MR);
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isTargetFunction(C))
    return;

  if (!isSrcListConsumer(Call, C))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    SVal ArgVal = Call.getArgSVal(i);
    if (const MemRegion *MR = ArgVal.getAsRegion()) {
      State = removeOwned(State, MR);
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS,
                                        CheckerContext &C) const {
  if (!isTargetFunction(C))
    return;

  ProgramStateRef State = C.getState();
  if (State->get<OwnedSrcListMap>().isEmpty())
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Memory leak: SrcList not freed on no-transfer path.", N);
  if (RS)
    report->addRange(RS->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memory leak of SrcList in sqlite3TriggerUpdateStep",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
