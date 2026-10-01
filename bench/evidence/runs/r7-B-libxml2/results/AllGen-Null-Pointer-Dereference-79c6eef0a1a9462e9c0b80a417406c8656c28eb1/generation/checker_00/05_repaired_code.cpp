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

using namespace clang;
using namespace ento;
using namespace taint;

// Map from allocation result symbol to whether it has been NULL-checked.
// false => unchecked, true => checked.
REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedAllocMap, SymbolRef, bool)

namespace {
class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Dereference before NULL check", "Null Pointer")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  bool isAllocator(const CallEvent &Call, CheckerContext &C) const;
  bool isDerefFunction(const CallEvent &Call, CheckerContext &C) const;
  SymbolRef getPointerSymbol(const Expr *E, CheckerContext &C) const;
  void reportBug(const CallEvent &Call, CheckerContext &C) const;
};
} // end anonymous namespace

bool SAGenTestChecker::isAllocator(const CallEvent &Call,
                                   CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  return ExprHasName(OriginExpr, "xmlStrdup", C) ||
         ExprHasName(OriginExpr, "strdup", C) ||
         ExprHasName(OriginExpr, "malloc", C) ||
         ExprHasName(OriginExpr, "calloc", C) ||
         ExprHasName(OriginExpr, "realloc", C);
}

bool SAGenTestChecker::isDerefFunction(const CallEvent &Call,
                                       CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  return ExprHasName(OriginExpr, "strlen", C) ||
         ExprHasName(OriginExpr, "strcmp", C) ||
         ExprHasName(OriginExpr, "strcpy", C) ||
         ExprHasName(OriginExpr, "strcat", C);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isAllocator(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = RetVal.getAsSymbol();
  if (!Sym)
    return;

  State = State->set<UncheckedAllocMap>(Sym, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isDerefFunction(Call, C))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
    SVal ArgVal = Call.getArgSVal(I);
    SymbolRef Sym = ArgVal.getAsSymbol();
    if (!Sym)
      continue;

    const bool *Checked = State->get<UncheckedAllocMap>(Sym);
    if (Checked && *Checked == false) {
      reportBug(Call, C);
      return;
    }
  }
}

SymbolRef SAGenTestChecker::getPointerSymbol(const Expr *E,
                                             CheckerContext &C) const {
  if (!E)
    return SymbolRef();

  E = E->IgnoreParenImpCasts();

  // Handle !ptr
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      return C.getState()->getSVal(Sub, C.getLocationContext()).getAsSymbol();
    }
  }

  // Handle ptr == NULL or ptr != NULL
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSIsNull = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);

      const Expr *PtrExpr = nullptr;
      if (LHSIsNull && !RHSIsNull)
        PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrExpr = LHS;

      if (PtrExpr)
        return C.getState()
            ->getSVal(PtrExpr, C.getLocationContext())
            .getAsSymbol();
    }
  }

  // Handle if (ptr)
  return C.getState()->getSVal(E, C.getLocationContext()).getAsSymbol();
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  SymbolRef Sym = getPointerSymbol(CondE, C);
  if (Sym) {
    const bool *Checked = State->get<UncheckedAllocMap>(Sym);
    if (Checked && *Checked == false) {
      State = State->set<UncheckedAllocMap>(Sym, true);
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::reportBug(const CallEvent &Call,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Dereferencing allocation result before NULL check", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of allocation result before NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
