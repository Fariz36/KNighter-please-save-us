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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedCreationMap, SymbolRef, bool)

namespace {
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked NULL return from hunk_from_entry",
                       "Null Dereference")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  bool isHunkFromEntry(const CallEvent &Call, CheckerContext &C) const;
  bool isGitVectorInsert(const CallEvent &Call, CheckerContext &C) const;
  SymbolRef getTestedSymbol(const Expr *CondE, CheckerContext &C) const;
  SymbolRef getSymbolFromExpr(const Expr *E, CheckerContext &C) const;
  void reportUncheckedUse(const CallEvent &Call, CheckerContext &C) const;
};

bool SAGenTestChecker::isHunkFromEntry(const CallEvent &Call,
                                       CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, "hunk_from_entry", C);
}

bool SAGenTestChecker::isGitVectorInsert(const CallEvent &Call,
                                         CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, "git_vector_insert", C);
}

SymbolRef SAGenTestChecker::getSymbolFromExpr(const Expr *E,
                                              CheckerContext &C) const {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  ProgramStateRef State = C.getState();
  SVal V = State->getSVal(E, C.getLocationContext());
  return V.getAsSymbol();
}

SymbolRef SAGenTestChecker::getTestedSymbol(const Expr *CondE,
                                            CheckerContext &C) const {
  if (!CondE)
    return nullptr;

  CondE = CondE->IgnoreParens();

  while (const auto *ICE = dyn_cast<ImplicitCastExpr>(CondE))
    CondE = ICE->getSubExpr()->IgnoreParens();
  while (const auto *CSE = dyn_cast<CStyleCastExpr>(CondE))
    CondE = CSE->getSubExpr()->IgnoreParens();

  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot)
      return getTestedSymbol(UO->getSubExpr(), C);
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParens();
      const Expr *RHS = BO->getRHS()->IgnoreParens();

      bool LZero = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RZero = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);

      if (!LZero) {
        llvm::APSInt LVal;
        if (EvaluateExprToInt(LVal, LHS, C) && LVal.isZero())
          LZero = true;
      }
      if (!RZero) {
        llvm::APSInt RVal;
        if (EvaluateExprToInt(RVal, RHS, C) && RVal.isZero())
          RZero = true;
      }

      if (LZero && !RZero)
        return getSymbolFromExpr(RHS, C);
      if (RZero && !LZero)
        return getSymbolFromExpr(LHS, C);
    }
  }

  return getSymbolFromExpr(CondE, C);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isHunkFromEntry(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SymbolRef Sym = Call.getReturnValue().getAsSymbol();
  if (!Sym)
    return;

  State = State->set<UncheckedCreationMap>(Sym, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isGitVectorInsert(Call, C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  SVal Arg = Call.getArgSVal(1);
  SymbolRef Sym = Arg.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  const bool *Unchecked = State->get<UncheckedCreationMap>(Sym);
  if (Unchecked && *Unchecked) {
    reportUncheckedUse(Call, C);
    State = State->remove<UncheckedCreationMap>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  SymbolRef Sym = getTestedSymbol(CondE, C);
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  if (State->get<UncheckedCreationMap>(Sym)) {
    State = State->remove<UncheckedCreationMap>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::reportUncheckedUse(const CallEvent &Call,
                                          CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked NULL return from hunk_from_entry used without check", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}
} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked NULL return from hunk_from_entry before use",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
