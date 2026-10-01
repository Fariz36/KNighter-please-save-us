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
#include "clang/AST/DeclCXX.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(UncheckedSimplifyReturns, SymbolRef)

namespace {

static bool isRegexpSimplify(const CallEvent &Call) {
  const CXXMethodDecl *MD = dyn_cast_or_null<CXXMethodDecl>(Call.getDecl());
  if (!MD)
    return false;
  if (MD->getName() != "Simplify")
    return false;
  const CXXRecordDecl *Parent = MD->getParent();
  return Parent && Parent->getName() == "Regexp";
}

static SymbolRef getSymbolFromSVal(SVal V) {
  if (SymbolRef Sym = V.getAsSymbol())
    return Sym;
  if (const MemRegion *MR = V.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (const auto *SR = dyn_cast<SymbolicRegion>(MR))
      return SR->getSymbol();
  }
  return nullptr;
}

static ProgramStateRef markChecked(ProgramStateRef State, SymbolRef Sym) {
  if (!Sym)
    return State;
  if (State->contains<UncheckedSimplifyReturns>(Sym))
    State = State->remove<UncheckedSimplifyReturns>(Sym);
  return State;
}

class SAGenTestChecker : public Checker<check::PostCall,
                                         check::PreCall,
                                         check::BranchCondition,
                                         check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked NULL return from Regexp::Simplify()",
                       "Null Dereference")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;

private:
  void reportBug(CheckerContext &C, SymbolRef Sym) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isRegexpSimplify(Call))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = getSymbolFromSVal(Ret);
  if (!Sym)
    return;

  State = State->add<UncheckedSimplifyReturns>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    SVal ArgV = Call.getArgSVal(i);
    SymbolRef Sym = getSymbolFromSVal(ArgV);
    if (Sym && State->contains<UncheckedSimplifyReturns>(Sym)) {
      reportBug(C, Sym);
      return;
    }
  }

  if (const auto *MC = dyn_cast<CXXMemberCall>(&Call)) {
    SVal ThisV = MC->getCXXThisVal();
    SymbolRef Sym = getSymbolFromSVal(ThisV);
    if (Sym && State->contains<UncheckedSimplifyReturns>(Sym)) {
      reportBug(C, Sym);
      return;
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();
  const Expr *PtrExpr = nullptr;

  const Expr *E = CondE->IgnoreParenCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      PtrExpr = UO->getSubExpr()->IgnoreParenCasts();
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
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
  } else {
    PtrExpr = E;
  }

  if (!PtrExpr)
    return;

  SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
  SymbolRef Sym = getSymbolFromSVal(PtrVal);
  if (Sym) {
    State = markChecked(State, Sym);
    if (State != C.getState())
      C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SymbolRef Sym = getSymbolFromSVal(Loc);
  if (Sym && State->contains<UncheckedSimplifyReturns>(Sym))
    reportBug(C, Sym);
}

void SAGenTestChecker::reportBug(CheckerContext &C, SymbolRef Sym) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked NULL return from Regexp::Simplify()", N);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked NULL return from Regexp::Simplify()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
