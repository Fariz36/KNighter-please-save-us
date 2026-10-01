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
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedNullPtrMap, SymbolRef, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked NULL pointer insertion",
                       "Null Pointer")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportUncheckedNullInsert(const CallEvent &Call,
                                 CheckerContext &C) const;
};

} // end anonymous namespace

static bool isHunkFromEntry(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, "hunk_from_entry", C);
}

static bool isGitVectorInsert(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, "git_vector_insert", C);
}

static const Expr *getNullCheckedPtrExpr(const Expr *Cond,
                                         CheckerContext &C) {
  if (!Cond)
    return nullptr;

  Cond = Cond->IgnoreParenCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      return UO->getSubExpr()->IgnoreParenCasts();
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      ASTContext &AC = C.getASTContext();
      bool LHSIsNull = LHS->isNullPointerConstant(
          AC, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          AC, Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && !RHSIsNull)
        return RHS;
      if (RHSIsNull && !LHSIsNull)
        return LHS;
    }
  } else {
    return Cond;
  }

  return nullptr;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isHunkFromEntry(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = RetVal.getAsSymbol();
  if (!Sym)
    return;

  State = State->set<UncheckedNullPtrMap>(Sym, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isGitVectorInsert(Call, C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  ProgramStateRef State = C.getState();
  SVal ArgVal = Call.getArgSVal(1);
  SymbolRef Sym = ArgVal.getAsSymbol();
  if (!Sym)
    return;

  const bool *Unchecked = State->get<UncheckedNullPtrMap>(Sym);
  if (Unchecked && *Unchecked) {
    reportUncheckedNullInsert(Call, C);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const Expr *PtrExpr = getNullCheckedPtrExpr(CondE, C);
  if (!PtrExpr)
    return;

  ProgramStateRef State = C.getState();
  SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
  SymbolRef Sym = PtrVal.getAsSymbol();
  if (!Sym)
    return;

  const bool *Unchecked = State->get<UncheckedNullPtrMap>(Sym);
  if (Unchecked && *Unchecked) {
    State = State->remove<UncheckedNullPtrMap>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::reportUncheckedNullInsert(const CallEvent &Call,
                                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Possible NULL pointer inserted without check", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects insertion of unchecked NULL pointer returned by hunk_from_entry",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
