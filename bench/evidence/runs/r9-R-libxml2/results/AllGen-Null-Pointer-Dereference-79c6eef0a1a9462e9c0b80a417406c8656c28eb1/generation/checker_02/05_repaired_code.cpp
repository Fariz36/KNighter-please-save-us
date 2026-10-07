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

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(UncheckedNullableSymbols, SymbolRef)

namespace {
class SAGenTestChecker
    : public Checker<check::PostCall, check::BranchCondition, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Null pointer passed to length operation before null check",
                       "Null Pointer Dereference")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  ProgramStateRef markChecked(ProgramStateRef State, SymbolRef Sym) const;
  ProgramStateRef markExprChecked(ProgramStateRef State, const Expr *E,
                                  CheckerContext &C) const;
  ProgramStateRef handleNullCheck(ProgramStateRef State, const Expr *E,
                                  CheckerContext &C) const;
  void reportBug(const CallEvent &Call, CheckerContext &C) const;
};
} // end anonymous namespace

ProgramStateRef SAGenTestChecker::markChecked(ProgramStateRef State,
                                              SymbolRef Sym) const {
  if (!Sym)
    return State;

  if (State->contains<UncheckedNullableSymbols>(Sym))
    return State->remove<UncheckedNullableSymbols>(Sym);

  return State;
}

ProgramStateRef SAGenTestChecker::markExprChecked(ProgramStateRef State,
                                                  const Expr *E,
                                                  CheckerContext &C) const {
  if (!E)
    return State;

  E = E->IgnoreParenImpCasts();
  SVal V = State->getSVal(E, C.getLocationContext());
  SymbolRef Sym = V.getAsSymbol(true);
  return markChecked(State, Sym);
}

ProgramStateRef SAGenTestChecker::handleNullCheck(ProgramStateRef State,
                                                  const Expr *E,
                                                  CheckerContext &C) const {
  if (!E)
    return State;

  E = E->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot)
      return handleNullCheck(State, UO->getSubExpr(), C);
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();

    if (Op == BO_LAnd || Op == BO_LOr) {
      State = handleNullCheck(State, BO->getLHS(), C);
      State = handleNullCheck(State, BO->getRHS(), C);
      return State;
    }

    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSIsNull =
          LHS->isNullPointerConstant(C.getASTContext(),
                                     Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull =
          RHS->isNullPointerConstant(C.getASTContext(),
                                     Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull != RHSIsNull) {
        const Expr *PtrExpr = LHSIsNull ? RHS : LHS;
        return markExprChecked(State, PtrExpr, C);
      }
    }
  }

  // Bare pointer condition such as `if (ptr)`.
  return markExprChecked(State, E, C);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "duplicator") &&
      !knighter::callIsRole(Call, "null_on_failure"))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = RetVal.getAsSymbol(true);
  if (!Sym)
    return;

  State = State->add<UncheckedNullableSymbols>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();
  State = handleNullCheck(State, CondE, C);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "length_of"))
    return;
  if (Call.getNumArgs() < 1)
    return;

  SVal Arg0 = Call.getArgSVal(0);
  SymbolRef Sym = Arg0.getAsSymbol(true);
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<UncheckedNullableSymbols>(Sym))
    return;

  reportBug(Call, C);
}

void SAGenTestChecker::reportBug(const CallEvent &Call,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Null pointer passed to length operation before null check", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects a null-on-failure/duplicator result passed to a length "
      "operation before null checking",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "duplicator": {"names": ["xmlStrdup"], "description": "returns a newly allocated copy of its input; may return NULL on failure"},
  "null_on_failure": {"names": ["xmlStrdup"], "description": "function that may return NULL on failure; its result must be checked before use"},
  "length_of": {"names": ["strlen"], "description": "computes the length of a null-terminated string; dereferences its pointer argument"},
  "allocator": {"names": ["xmlMalloc"], "description": "allocates a block of memory; may return NULL on failure"},
  "deallocator": {"names": ["xmlFree"], "description": "frees memory previously allocated by an allocator or duplicator"}
}
*/
