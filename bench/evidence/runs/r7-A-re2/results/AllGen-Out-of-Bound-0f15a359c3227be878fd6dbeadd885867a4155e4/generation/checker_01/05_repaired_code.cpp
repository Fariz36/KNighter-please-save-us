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

#include "clang/AST/ExprCXX.h"
#include "clang/AST/Expr.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(CheckedNonEmptyMap, SymbolRef, bool)

namespace {
class SAGenTestChecker : public Checker<check::BranchCondition, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Container index underflow", "Memory access")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(CheckerContext &C, const Stmt *S) const;
  bool isMinusOne(const Expr *E, const Expr *&Base, CheckerContext &C) const;
  SymbolRef getSymbolRef(const Expr *E, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) return;
  CondE = CondE->IgnoreParenCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO) return;

  const Expr *VarExpr = nullptr;
  if (BO->getOpcode() == BO_GT) {
    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
    llvm::APSInt RHSVal;
    if (EvaluateExprToInt(RHSVal, RHS, C) && RHSVal == 0) {
      VarExpr = LHS;
    }
  } else if (BO->getOpcode() == BO_LT) {
    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
    llvm::APSInt LHSVal;
    if (EvaluateExprToInt(LHSVal, LHS, C) && LHSVal == 0) {
      VarExpr = RHS;
    }
  } else if (BO->getOpcode() == BO_NE) {
    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
    llvm::APSInt LHSVal, RHSVal;
    bool LHSConst = EvaluateExprToInt(LHSVal, LHS, C);
    bool RHSConst = EvaluateExprToInt(RHSVal, RHS, C);
    if (LHSConst && LHSVal == 0) {
      VarExpr = RHS;
    } else if (RHSConst && RHSVal == 0) {
      VarExpr = LHS;
    }
  }

  if (!VarExpr) return;

  SymbolRef Sym = getSymbolRef(VarExpr, C);
  if (!Sym) return;

  ProgramStateRef State = C.getState();
  State = State->set<CheckedNonEmptyMap>(Sym, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  const CXXOperatorCallExpr *OO = dyn_cast_or_null<CXXOperatorCallExpr>(OriginExpr);
  if (!OO || OO->getOperator() != OO_Subscript) return;

  const Expr *BaseExpr = nullptr;
  const Expr *IndexExpr = nullptr;
  for (unsigned i = 0; i < OO->getNumArgs(); ++i) {
    const Expr *Arg = OO->getArg(i);
    if (isMinusOne(Arg, BaseExpr, C)) {
      IndexExpr = Arg;
      break;
    }
  }
  if (!IndexExpr) return;

  llvm::APSInt BaseVal;
  if (EvaluateExprToInt(BaseVal, BaseExpr, C)) {
    if (BaseVal > 0) {
      return;
    } else {
      reportBug(C, IndexExpr);
      return;
    }
  }

  SymbolRef Sym = getSymbolRef(BaseExpr, C);
  if (!Sym) return;

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<CheckedNonEmptyMap>(Sym);
  if (Checked && *Checked) return;

  reportBug(C, IndexExpr);
}

void SAGenTestChecker::reportBug(CheckerContext &C, const Stmt *S) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Accessing last element with index -1 without checking container is non-empty.", N);
  R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));
}

bool SAGenTestChecker::isMinusOne(const Expr *E, const Expr *&Base, CheckerContext &C) const {
  E = E->IgnoreParenImpCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Sub) return false;
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  llvm::APSInt RHSVal;
  if (!EvaluateExprToInt(RHSVal, RHS, C)) return false;
  if (RHSVal != 1) return false;
  Base = BO->getLHS()->IgnoreParenImpCasts();
  return true;
}

SymbolRef SAGenTestChecker::getSymbolRef(const Expr *E, CheckerContext &C) const {
  if (!E) return nullptr;
  SVal V = C.getState()->getSVal(E, C.getLocationContext());
  return V.getAsSymbol();
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects accessing last element with index -1 without checking non-empty",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
