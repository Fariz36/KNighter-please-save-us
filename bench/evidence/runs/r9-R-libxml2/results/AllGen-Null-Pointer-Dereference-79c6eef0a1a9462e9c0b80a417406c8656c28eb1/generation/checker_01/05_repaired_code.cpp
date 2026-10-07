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

REGISTER_SET_WITH_PROGRAMSTATE(UncheckedDupSet, SymbolRef)

namespace {

class SAGenTestChecker
    : public Checker<check::PostCall, check::BranchCondition, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use before NULL check",
                       "Null pointer dereference")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "duplicator") &&
      !knighter::callIsRole(Call, "null_on_failure"))
    return;

  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = Ret.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<UncheckedDupSet>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  Cond = Cond->IgnoreParenImpCasts();

  const Expr *PtrExpr = nullptr;

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      PtrExpr = UO->getSubExpr()->IgnoreParenImpCasts();
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      ASTContext &AC = C.getASTContext();
      bool LHSIsNull =
          LHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull =
          RHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull && !RHSIsNull)
        PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrExpr = LHS;
    }
  }

  if (!PtrExpr)
    PtrExpr = Cond;

  ProgramStateRef State = C.getState();
  SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
  SymbolRef Sym = PtrVal.getAsSymbol();
  if (!Sym)
    return;

  if (State->contains<UncheckedDupSet>(Sym)) {
    State = State->remove<UncheckedDupSet>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "length_of"))
    return;

  if (Call.getNumArgs() == 0)
    return;

  ProgramStateRef State = C.getState();
  SVal Arg = Call.getArgSVal(0);
  SymbolRef Sym = Arg.getAsSymbol();
  if (!Sym)
    return;

  if (!State->contains<UncheckedDupSet>(Sym))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Result of duplicator may be NULL and is used before NULL check", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of a possibly NULL duplicator result before a NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "duplicator": {"names": ["xmlStrdup"], "description": "returns a newly allocated copy of its input; may return NULL on allocation failure"},
  "null_on_failure": {"names": ["xmlStrdup"], "description": "may return NULL on failure, so its result must be checked before use"},
  "length_of": {"names": ["strlen"], "description": "computes the length of a C string by dereferencing the pointer; the argument must be non-NULL"}
}
*/
