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

REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedNullPtrMap, const MemRegion *, bool)

namespace {
class SAGenTestChecker : public Checker<eval::Call,
                                        check::PostCall,
                                        check::PreCall,
                                        check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Null dereference", "Null dereference")) {}

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportNullDeref(const CallEvent &Call, CheckerContext &C) const;
  const Expr *getNullCheckedPtr(const Expr *Cond, CheckerContext &C) const;
};
} // end anonymous namespace

bool SAGenTestChecker::evalCall(const CallEvent &Call, CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "allocator"))
    return false;

  const Expr *CE = Call.getOriginExpr();
  if (!CE)
    return false;

  ProgramStateRef State = C.getState();
  SValBuilder &SVB = C.getSValBuilder();
  const LocationContext *LCtx = C.getLocationContext();
  unsigned Count = C.blockCount();
  SVal RetVal = SVB.getConjuredHeapSymbolVal(CE, LCtx, Count);

  State = State->BindExpr(CE, LCtx, RetVal);
  C.addTransition(State);
  return true;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "allocator"))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  const MemRegion *MR = RetVal.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  State = State->set<UncheckedNullPtrMap>(MR, false);
  C.addTransition(State);
}

const Expr *SAGenTestChecker::getNullCheckedPtr(const Expr *Cond, CheckerContext &C) const {
  if (!Cond)
    return nullptr;

  Cond = Cond->IgnoreParenCasts();
  ASTContext &AC = C.getASTContext();

  // Handle !ptr
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      return UO->getSubExpr()->IgnoreParenCasts();
    }
  }

  // Handle ptr == NULL, NULL == ptr, ptr != NULL, NULL != ptr
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      bool LHSIsNull = LHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull && !RHSIsNull)
        return RHS;
      if (RHSIsNull && !LHSIsNull)
        return LHS;
    }
  }

  // Handle bare ptr (if (ptr))
  return Cond;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  const Expr *PtrExpr = getNullCheckedPtr(Cond, C);
  if (!PtrExpr)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = getMemRegionFromExpr(PtrExpr, C);
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  const bool *Checked = State->get<UncheckedNullPtrMap>(MR);
  if (Checked && *Checked == false) {
    State = State->set<UncheckedNullPtrMap>(MR, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "length_of"))
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
  const bool *Checked = State->get<UncheckedNullPtrMap>(MR);
  if (Checked && *Checked == false) {
    reportNullDeref(Call, C);
  }
}

void SAGenTestChecker::reportNullDeref(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Result of null-on-failure allocation used by length_of before NULL check", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of null-on-failure allocation by length_of before NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {"names": ["xmlMalloc", "xmlStrdup"], "description": "Memory allocation or string duplication function that returns NULL on failure."},
  "length_of": {"names": ["strlen"], "description": "Function that computes the length of a string by dereferencing its pointer argument."}
}
*/
