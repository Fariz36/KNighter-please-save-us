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
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedHunkPtrMap, SymbolRef, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Unchecked hunk_from_entry return", "Memory Error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportUncheckedUse(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee || Callee->getName() != "hunk_from_entry")
    return;

  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = Ret.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<UncheckedHunkPtrMap>(Sym, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee || Callee->getName() != "git_vector_insert")
    return;

  if (Call.getNumArgs() < 2)
    return;

  SVal ArgVal = Call.getArgSVal(1);
  SymbolRef Sym = ArgVal.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  const bool *Unchecked = State->get<UncheckedHunkPtrMap>(Sym);
  if (Unchecked && *Unchecked) {
    reportUncheckedUse(Call, C);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  CondE = CondE->IgnoreParenImpCasts();

  const Expr *PtrExpr = nullptr;

  // Pattern 1: !ptr
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      PtrExpr = UO->getSubExpr()->IgnoreParenImpCasts();
    }
  }
  // Pattern 2: ptr == NULL or NULL == ptr, ptr != NULL or NULL != ptr
  else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && !RHSIsNull) {
        PtrExpr = RHS;
      } else if (RHSIsNull && !LHSIsNull) {
        PtrExpr = LHS;
      }
    }
  }
  // Pattern 3: ptr alone (e.g., if (ptr))
  else {
    PtrExpr = CondE;
  }

  if (PtrExpr) {
    SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
    SymbolRef Sym = PtrVal.getAsSymbol();
    if (Sym) {
      if (State->get<UncheckedHunkPtrMap>(Sym)) {
        State = State->remove<UncheckedHunkPtrMap>(Sym);
      }
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::reportUncheckedUse(const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked hunk_from_entry() return passed to git_vector_insert()", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked hunk_from_entry() return values passed to git_vector_insert()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
