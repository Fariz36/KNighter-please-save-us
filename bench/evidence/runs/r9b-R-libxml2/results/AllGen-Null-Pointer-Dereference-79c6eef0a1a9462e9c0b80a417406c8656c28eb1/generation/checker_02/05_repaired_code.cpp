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

static SymbolRef getSymbolFromSVal(SVal V) {
  if (SymbolRef Sym = V.getAsLocSymbol())
    return Sym;
  return V.getAsSymbol();
}

static SymbolRef getNullCheckedSymbol(const Expr *Cond, CheckerContext &C) {
  if (!Cond)
    return nullptr;

  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      SVal V = C.getState()->getSVal(Sub, C.getLocationContext());
      return getSymbolFromSVal(V);
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      ASTContext &ACtx = C.getASTContext();
      bool LNull = LHS->isNullPointerConstant(ACtx, Expr::NPC_ValueDependentIsNull);
      bool RNull = RHS->isNullPointerConstant(ACtx, Expr::NPC_ValueDependentIsNull);

      const Expr *PtrExpr = nullptr;
      if (LNull && !RNull)
        PtrExpr = RHS;
      else if (RNull && !LNull)
        PtrExpr = LHS;

      if (PtrExpr) {
        SVal V = C.getState()->getSVal(PtrExpr, C.getLocationContext());
        return getSymbolFromSVal(V);
      }
    }
  }

  SVal V = C.getState()->getSVal(Cond, C.getLocationContext());
  return getSymbolFromSVal(V);
}

class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked NULL from duplicator",
                       "Null pointer dereference")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportUncheckedDup(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "duplicator"))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = getSymbolFromSVal(RetVal);
  if (!Sym)
    return;

  State = State->add<UncheckedDupSet>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "length_of"))
    return;

  if (Call.getNumArgs() < 1)
    return;

  ProgramStateRef State = C.getState();
  SVal Arg0 = Call.getArgSVal(0);
  SymbolRef Sym = getSymbolFromSVal(Arg0);
  if (!Sym)
    return;

  if (State->contains<UncheckedDupSet>(Sym))
    reportUncheckedDup(Call, C);
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
  if (State->contains<UncheckedDupSet>(Sym)) {
    State = State->remove<UncheckedDupSet>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::reportUncheckedDup(const CallEvent &Call,
                                          CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Length calculated on unchecked duplicator result", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects length-of use on unchecked duplicator results",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "duplicator": {"names": ["xmlStrdup"], "description": "returns a newly allocated copy of its input string, or NULL on failure"},
  "length_of": {"names": ["strlen"], "description": "computes the length of a C string, dereferencing its pointer argument"}
}
*/
