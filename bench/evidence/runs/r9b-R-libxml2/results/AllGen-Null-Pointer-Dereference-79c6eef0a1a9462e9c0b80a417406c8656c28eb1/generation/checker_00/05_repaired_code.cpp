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
#include "llvm/Support/Casting.h"
#include "knighter/roles.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(UncheckedNullOnFailure, SymbolRef)

namespace {

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::BranchCondition,
                                        check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Length of Unchecked Nullable Result",
                       "Null Dereference")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

static SymbolRef getSymbolFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenCasts();
  SVal V = C.getState()->getSVal(E, C.getLocationContext());
  return V.getAsSymbol();
}

static SymbolRef getNullCheckedSymbol(const Expr *Cond, CheckerContext &C) {
  if (!Cond)
    return nullptr;

  Cond = Cond->IgnoreParens();

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot)
      return getSymbolFromExpr(UO->getSubExpr(), C);
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull && !RHSIsNull)
        return getSymbolFromExpr(RHS, C);
      if (RHSIsNull && !LHSIsNull)
        return getSymbolFromExpr(LHS, C);
    }
  }

  return getSymbolFromExpr(Cond, C);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "null_on_failure"))
    return;

  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = RetVal.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<UncheckedNullOnFailure>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  SymbolRef Sym = getNullCheckedSymbol(Cond, C);
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<UncheckedNullOnFailure>(Sym))
    return;

  State = State->remove<UncheckedNullOnFailure>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "length_of"))
    return;

  if (Call.getNumArgs() < 1)
    return;

  ProgramStateRef State = C.getState();
  SVal Arg = Call.getArgSVal(0);
  SymbolRef Sym = Arg.getAsSymbol();
  if (!Sym)
    return;

  if (!State->contains<UncheckedNullOnFailure>(Sym))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "length_of called on unchecked nullable result", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects length_of calls on results of null_on_failure functions before NULL checking",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "null_on_failure": {"names": ["xmlStrdup"], "description": "function that may return NULL on failure; its result must be checked before dereference"},
  "length_of": {"names": ["strlen"], "description": "function that computes the length of a C string, dereferencing its pointer argument"},
  "duplicator": {"names": ["xmlStrdup"], "description": "function that returns a newly allocated copy of its input"},
  "allocator": {"names": ["xmlMalloc"], "description": "function that allocates memory"},
  "deallocator": {"names": ["xmlFree"], "description": "function that frees memory"}
}
*/
