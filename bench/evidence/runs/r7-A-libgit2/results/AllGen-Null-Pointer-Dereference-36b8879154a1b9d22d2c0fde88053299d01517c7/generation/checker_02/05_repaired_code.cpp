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
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedHunkMap, SymbolRef, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedHunkRegionMap, const MemRegion *, bool)

namespace {
class SAGenTestChecker : public Checker<check::PostCall,
                                        check::BranchCondition,
                                        check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked hunk_from_entry() result",
                       "Null pointer")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const Expr *CE = Call.getOriginExpr();
  if (!CE || !ExprHasName(CE, "hunk_from_entry", C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();

  if (SymbolRef Sym = Ret.getAsSymbol()) {
    State = State->set<UncheckedHunkMap>(Sym, true);
  } else if (const MemRegion *MR = Ret.getAsRegion()) {
    MR = MR->getBaseRegion();
    State = State->set<UncheckedHunkRegionMap>(MR, true);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  ProgramStateRef State = C.getState();
  const DeclRefExpr *DRE = findSpecificTypeInChildren<DeclRefExpr>(Condition);
  if (!DRE) {
    C.addTransition(State);
    return;
  }

  SVal V = State->getSVal(DRE, C.getLocationContext());

  if (SymbolRef Sym = V.getAsSymbol()) {
    if (State->get<UncheckedHunkMap>(Sym))
      State = State->remove<UncheckedHunkMap>(Sym);
  }

  if (const MemRegion *MR = V.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (State->get<UncheckedHunkRegionMap>(MR))
      State = State->remove<UncheckedHunkRegionMap>(MR);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *CE = Call.getOriginExpr();
  if (!CE || !ExprHasName(CE, "git_vector_insert", C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  SVal Arg = Call.getArgSVal(1);
  ProgramStateRef State = C.getState();
  bool Unchecked = false;

  if (SymbolRef Sym = Arg.getAsSymbol()) {
    const bool *B = State->get<UncheckedHunkMap>(Sym);
    if (B && *B)
      Unchecked = true;
  } else if (const MemRegion *MR = Arg.getAsRegion()) {
    MR = MR->getBaseRegion();
    const bool *B = State->get<UncheckedHunkRegionMap>(MR);
    if (B && *B)
      Unchecked = true;
  }

  if (Unchecked)
    reportBug(Call, C);
}

void SAGenTestChecker::reportBug(const CallEvent &Call,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "hunk_from_entry() result used without NULL check", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects hunk_from_entry() results used without NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
