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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(UncheckedNullRegions, const MemRegion *)

namespace {

static const MemRegion *getRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;

  // Evaluate the original expression first. Do not strip implicit casts
  // before this call; LValueToRValue casts are needed to load pointer values.
  const MemRegion *R = getMemRegionFromExpr(E, C);
  if (R)
    return R->getBaseRegion();

  // If the expression is a cast that does not hide a load, try its operand.
  const Expr *Sub = E->IgnoreParens();
  if (const auto *Cast = dyn_cast<CastExpr>(Sub)) {
    if (Cast->getCastKind() != CK_LValueToRValue)
      return getRegionFromExpr(Cast->getSubExpr(), C);
  }

  return nullptr;
}

static const MemRegion *getNullCheckedRegion(const Expr *Cond,
                                             CheckerContext &C) {
  if (!Cond)
    return nullptr;

  const Expr *E = Cond->IgnoreParens();

  // if (!ptr)
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot)
      return getRegionFromExpr(UO->getSubExpr(), C);
  }

  // if (ptr == NULL) / if (ptr != NULL)
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();
      ASTContext &AC = C.getASTContext();

      bool LHSIsNull = LHS->isNullPointerConstant(
          AC, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          AC, Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull && !RHSIsNull)
        return getRegionFromExpr(RHS, C);
      if (RHSIsNull && !LHSIsNull)
        return getRegionFromExpr(LHS, C);
    }
  }

  // if (ptr)
  return getRegionFromExpr(Cond, C);
}

class SAGenTestChecker : public Checker<eval::Call,
                                       check::PostCall,
                                       check::BranchCondition,
                                       check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use Before NULL Check", "Null Pointer")) {}

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition,
                            CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportUseBeforeCheck(const CallEvent &Call, CheckerContext &C) const;
};

bool SAGenTestChecker::evalCall(const CallEvent &Call,
                                CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "null_on_failure"))
    return false;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  ProgramStateRef State = C.getState();
  SVal RetVal = C.getSValBuilder().getConjuredHeapSymbolVal(
      Origin, C.getLocationContext(), 0);
  State = State->BindExpr(Origin, C.getLocationContext(), RetVal);
  C.addTransition(State);
  return true;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "null_on_failure"))
    return;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = State->getSVal(Origin, C.getLocationContext());
  const MemRegion *R = RetVal.getAsRegion();
  if (!R)
    return;

  R = R->getBaseRegion();
  State = State->add<UncheckedNullRegions>(R);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond) {
    C.addTransition(C.getState());
    return;
  }

  ProgramStateRef State = C.getState();
  if (const MemRegion *R = getNullCheckedRegion(Cond, C))
    State = State->remove<UncheckedNullRegions>(R);

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "length_of"))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *Arg = Call.getArgExpr(0);
  const MemRegion *R = getRegionFromExpr(Arg, C);
  if (!R)
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<UncheckedNullRegions>(R))
    reportUseBeforeCheck(Call, C);
}

void SAGenTestChecker::reportUseBeforeCheck(const CallEvent &Call,
                                            CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Use of possibly NULL pointer before NULL check", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of a NULL-on-failure result before its NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "null_on_failure": {
    "names": ["xmlStrdup", "xmlMalloc"],
    "description": "allocation or duplication function that may return NULL on failure; its result must be NULL-checked before dereference"
  },
  "length_of": {
    "names": ["strlen"],
    "description": "function that dereferences its pointer argument, e.g., computes string length"
  }
}
*/
