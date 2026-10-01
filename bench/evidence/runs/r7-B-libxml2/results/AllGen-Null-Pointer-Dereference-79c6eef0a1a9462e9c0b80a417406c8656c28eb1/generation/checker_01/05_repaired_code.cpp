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

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "clang/AST/OperationKinds.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Map: allocation region -> true if allocated but not yet NULL-checked
REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedAllocMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker
    : public Checker<eval::Call,
                     check::PostCall,
                     check::PreCall,
                     check::BranchCondition,
                     check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use of unchecked allocation result",
                       "Memory Management")) {}

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool isLoad, const Stmt *S,
                     CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C,
                 const MemRegion *MR) const;
};

} // end anonymous namespace

// Helper: check whether the call is xmlStrdup
static bool isXmlStrdup(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, "xmlStrdup", C);
}

// Helper: check whether the call is strlen
static bool isStrlen(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, "strlen", C);
}

// Model xmlStrdup as an allocation that returns a fresh heap region.
bool SAGenTestChecker::evalCall(const CallEvent &Call,
                                CheckerContext &C) const {
  if (!isXmlStrdup(Call, C))
    return false;

  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;

  const CallExpr *CE = dyn_cast<CallExpr>(E);
  if (!CE)
    return false;

  SValBuilder &SVB = C.getSValBuilder();
  const LocationContext *LCtx = C.getLocationContext();
  unsigned Count = C.blockCount();
  DefinedSVal RetVal =
      SVB.getConjuredHeapSymbolVal(CE, LCtx, Count).castAs<DefinedSVal>();

  ProgramStateRef State = C.getState();
  State = State->BindExpr(CE, C.getLocationContext(), RetVal);
  C.addTransition(State);
  return true;
}

// After an xmlStrdup call, remember the returned region as unchecked.
void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isXmlStrdup(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  const MemRegion *MR = RetVal.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  State = State->set<UncheckedAllocMap>(MR, true);
  C.addTransition(State);
}

// If a NULL check is performed, mark the region as checked.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenCasts();

  auto MarkChecked = [&](const Expr *PtrExpr) {
    SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
    const MemRegion *MR = PtrVal.getAsRegion();
    if (!MR)
      return;

    MR = MR->getBaseRegion();
    if (!MR)
      return;

    const bool *Unchecked = State->get<UncheckedAllocMap>(MR);
    if (Unchecked && *Unchecked) {
      State = State->set<UncheckedAllocMap>(MR, false);
    }
  };

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      MarkChecked(UO->getSubExpr()->IgnoreParenCasts());
    }
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      bool LHSIsNull = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull && !RHSIsNull)
        MarkChecked(RHS);
      else if (RHSIsNull && !LHSIsNull)
        MarkChecked(LHS);
    }
  } else {
    // if (ptr)
    MarkChecked(CondE);
  }

  C.addTransition(State);
}

// Before strlen, check if its argument is an unchecked allocation.
void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isStrlen(Call, C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  SVal Arg0 = Call.getArgSVal(0);
  const MemRegion *MR = Arg0.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Unchecked = State->get<UncheckedAllocMap>(MR);
  if (Unchecked && *Unchecked) {
    reportBug(Call, C, MR);
  }
}

// Catch direct dereferences like *ptr or ptr[i].
void SAGenTestChecker::checkLocation(SVal Loc, bool isLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!isLoad)
    return;

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Unchecked = State->get<UncheckedAllocMap>(MR);
  if (Unchecked && *Unchecked) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Dereference of unchecked allocation result", N);
    Report->addRange(S->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

void SAGenTestChecker::reportBug(const CallEvent &Call, CheckerContext &C,
                                 const MemRegion *MR) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Use of xmlStrdup result before NULL check", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of xmlStrdup result before NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
