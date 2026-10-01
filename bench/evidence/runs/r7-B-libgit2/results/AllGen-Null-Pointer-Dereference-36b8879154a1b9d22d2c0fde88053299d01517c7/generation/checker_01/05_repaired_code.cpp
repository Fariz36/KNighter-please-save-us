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
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(UncheckedHunkSet, SymbolRef)

namespace {

static bool isCallTo(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const IdentifierInfo *ID = Call.getCalleeIdentifier();
  if (!ID || ID->getName() != Name)
    return false;

  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, Name, C);
}

static SymbolRef getTestedSymbol(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot)
      return getTestedSymbol(UO->getSubExpr(), C);
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      ASTContext &AC = C.getASTContext();
      bool LNull = LHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);
      bool RNull = RHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);

      if (LNull && !RNull)
        return getTestedSymbol(RHS, C);
      if (RNull && !LNull)
        return getTestedSymbol(LHS, C);
    }
  }

  QualType Ty = E->getType();
  if (Ty->isPointerType()) {
    SVal V = C.getState()->getSVal(E, C.getLocationContext());
    return V.getAsSymbol();
  }

  return nullptr;
}

class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked NULL Return", "Null Pointer")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isCallTo(Call, "hunk_from_entry", C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = Ret.getAsSymbol();
  if (!Sym)
    return;

  State = State->add<UncheckedHunkSet>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();
  SymbolRef Sym = getTestedSymbol(CondE, C);
  if (Sym && State->contains<UncheckedHunkSet>(Sym)) {
    State = State->remove<UncheckedHunkSet>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isCallTo(Call, "git_vector_insert", C))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
    SVal ArgVal = Call.getArgSVal(I);
    SymbolRef Sym = ArgVal.getAsSymbol();
    if (Sym && State->contains<UncheckedHunkSet>(Sym)) {
      reportBug(Call, C);
      return;
    }
  }
}

void SAGenTestChecker::reportBug(const CallEvent &Call,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked NULL return from hunk_from_entry", N);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked NULL returns from hunk_from_entry inserted into a git_vector",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
