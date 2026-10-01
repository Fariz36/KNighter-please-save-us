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
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps
REGISTER_MAP_WITH_PROGRAMSTATE(OwnershipMap, SymbolRef, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(FreedByCalleeMap, const MemRegion *, bool)

namespace {

// Helper: Determine if an assumption implies a symbol is NULL.
static SymbolRef getSymbolAssumedNull(SVal Cond, bool Assumption) {
  SymbolRef Sym = Cond.getAsSymbol();
  if (!Sym)
    return nullptr;

  const SymExpr *SE = Sym;
  if (!SE)
    return nullptr;

  // Case 1: Condition is the symbol itself (e.g., if (p))
  if (isa<SymbolData>(SE)) {
    if (!Assumption)
      return Sym;
    return nullptr;
  }

  // Case 2: Condition is a binary expression (e.g., p == NULL)
  if (const auto *BSE = dyn_cast<BinarySymExpr>(SE)) {
    unsigned Op = BSE->getOpcode();
    bool IsEq = (Op == BO_EQ);
    bool IsNe = (Op == BO_NE);
    if (!IsEq && !IsNe)
      return nullptr;

    bool ImpliesEq = (IsEq && Assumption) || (IsNe && !Assumption);
    if (!ImpliesEq)
      return nullptr;

    // Find the symbol compared to zero.
    if (const auto *SIE = dyn_cast<SymIntExpr>(BSE)) {
      if (SIE->getRHS().isZero()) {
        return SIE->getLHS();
      }
    } else if (const auto *ISE = dyn_cast<IntSymExpr>(BSE)) {
      if (ISE->getLHS().isZero()) {
        return ISE->getRHS();
      }
    }
  }

  return nullptr;
}

class SAGenTestChecker : public Checker<eval::Assume, check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double Free", "Memory Management")) {}

  ProgramStateRef evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

ProgramStateRef SAGenTestChecker::evalAssume(ProgramStateRef State, SVal Cond, bool Assumption) const {
  SymbolRef NullSym = getSymbolAssumedNull(Cond, Assumption);
  if (!NullSym)
    return State;

  const MemRegion * const *InputRegionPtr = State->get<OwnershipMap>(NullSym);
  if (!InputRegionPtr)
    return State;

  const MemRegion *InputRegion = *InputRegionPtr;
  if (!InputRegion)
    return State;

  State = State->set<FreedByCalleeMap>(InputRegion, true);
  return State;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "xmlNewIOInputStream", C))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef RetSym = RetVal.getAsSymbol(true);
  if (!RetSym)
    return;

  if (Call.getNumArgs() < 2)
    return;

  SVal Arg1 = Call.getArgSVal(1);
  const MemRegion *InputRegion = Arg1.getAsRegion();
  if (!InputRegion)
    return;

  InputRegion = InputRegion->getBaseRegion();
  if (!InputRegion)
    return;

  State = State->set<OwnershipMap>(RetSym, InputRegion);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "xmlFreeParserInputBuffer", C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  SVal Arg0 = Call.getArgSVal(0);
  const MemRegion *Region = Arg0.getAsRegion();
  if (!Region)
    return;

  Region = Region->getBaseRegion();
  if (!Region)
    return;

  ProgramStateRef State = C.getState();
  const bool *Freed = State->get<FreedByCalleeMap>(Region);
  if (Freed && *Freed) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Double free: buffer already freed by xmlNewIOInputStream on failure", N);
    Report->addRange(Call.getSourceRange());
    C.emitReport(std::move(Report));
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free caused by caller-side cleanup of a resource whose ownership was transferred to xmlNewIOInputStream",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
