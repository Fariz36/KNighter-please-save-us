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
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedDupMap, const MemRegion *, bool)

namespace {
class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Null Dereference",
                       "Dereference of possibly null pointer")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  static const Expr *getCheckedPtrExpr(const Expr *E, ASTContext &ACtx);
};

const Expr *SAGenTestChecker::getCheckedPtrExpr(const Expr *E,
                                                ASTContext &ACtx) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      return getCheckedPtrExpr(UO->getSubExpr(), ACtx);
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(
          ACtx, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          ACtx, Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && !RHSIsNull)
        return getCheckedPtrExpr(RHS, ACtx);
      if (RHSIsNull && !LHSIsNull)
        return getCheckedPtrExpr(LHS, ACtx);
      return nullptr;
    }
    return nullptr;
  } else {
    // Direct pointer expression (e.g., if (ptr))
    return E;
  }
  return nullptr;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "duplicator") &&
      !knighter::callIsRole(Call, "null_on_failure"))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  const MemRegion *R = Ret.getAsRegion();
  if (R) {
    State = State->set<UncheckedDupMap>(R, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "length_of"))
    return;

  ProgramStateRef State = C.getState();
  if (Call.getNumArgs() < 1)
    return;

  SVal Arg = Call.getArgSVal(0);
  const MemRegion *R = Arg.getAsRegion();
  if (!R)
    return;

  const bool *Unchecked = State->get<UncheckedDupMap>(R);
  if (Unchecked && *Unchecked) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Potential NULL dereference: duplicator result passed to length_of "
        "before NULL check",
        N);
    report->addRange(Call.getSourceRange());
    C.emitReport(std::move(report));

    State = State->remove<UncheckedDupMap>(R);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  const Expr *PtrExpr = getCheckedPtrExpr(CondE, C.getASTContext());
  if (PtrExpr) {
    SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
    const MemRegion *R = PtrVal.getAsRegion();
    if (R) {
      if (State->get<UncheckedDupMap>(R)) {
        State = State->remove<UncheckedDupMap>(R);
      }
    }
  }
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects NULL dereference when duplicator result is passed to length_of "
      "before NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "duplicator": {"names": ["xmlStrdup"], "description": "returns a newly allocated copy of its input; may return NULL on allocation failure"},
  "null_on_failure": {"names": ["xmlStrdup"], "description": "function that may return NULL when its operation fails"},
  "length_of": {"names": ["strlen"], "description": "computes the length of a null-terminated string/array; requires a non-null pointer"},
  "deallocator": {"names": ["xmlFree"], "description": "frees memory or an object; the pointer must not be used afterwards"}
}
*/
