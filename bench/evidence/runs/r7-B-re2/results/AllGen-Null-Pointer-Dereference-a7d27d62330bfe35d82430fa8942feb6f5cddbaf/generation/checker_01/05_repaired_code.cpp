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
#include "clang/AST/DeclCXX.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// false => pointer may be NULL and has not been null-checked yet.
// true  => pointer has been null-checked.
REGISTER_MAP_WITH_PROGRAMSTATE(NullablePtrMap, SymbolRef, bool)

namespace {

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::BranchCondition,
    check::Location,
    check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Null Pointer Dereference",
                       "Null Dereference")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition,
                            CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportNullDeref(CheckerContext &C, const Stmt *S) const;
};

} // end anonymous namespace

static bool isOrStrings(const CallEvent &Call) {
  const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return false;

  if (FD->getNameAsString() != "OrStrings")
    return false;

  const auto *MD = dyn_cast<CXXMethodDecl>(FD);
  if (!MD)
    return false;

  const auto *RD = MD->getParent();
  return RD && RD->getNameAsString() == "Prefilter";
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isOrStrings(Call))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = Ret.getAsSymbol();
  if (!Sym)
    return;

  State = State->set<NullablePtrMap>(Sym, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenImpCasts();

  const Expr *PtrE = nullptr;

  // if (!ptr)
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot)
      PtrE = UO->getSubExpr()->IgnoreParenImpCasts();
  }
  // if (ptr == 0) / if (0 == ptr) / if (ptr != 0) / if (0 != ptr)
  else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSIsNull = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull && !RHSIsNull)
        PtrE = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrE = LHS;
    }
  }
  // if (ptr)
  else {
    PtrE = CondE;
  }

  if (!PtrE)
    return;

  SVal V = State->getSVal(PtrE, C.getLocationContext());
  SymbolRef Sym = V.getAsSymbol();
  if (!Sym)
    return;

  const bool *Checked = State->get<NullablePtrMap>(Sym);
  if (Checked && !*Checked) {
    State = State->set<NullablePtrMap>(Sym, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  SymbolRef Sym = Loc.getAsSymbol(/*IncludeBaseRegions=*/true);
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<NullablePtrMap>(Sym);
  if (Checked && !*Checked)
    reportNullDeref(C, S);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const auto *MC = dyn_cast<CXXMemberCall>(&Call);
  if (!MC)
    return;

  SVal ThisVal = MC->getCXXThisVal();
  SymbolRef Sym = ThisVal.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<NullablePtrMap>(Sym);
  if (Checked && !*Checked)
    reportNullDeref(C, Call.getOriginExpr());
}

void SAGenTestChecker::reportNullDeref(CheckerContext &C,
                                       const Stmt *S) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Null pointer dereference: Prefilter::OrStrings() may return NULL", N);

  if (S)
    Report->addRange(S->getSourceRange());

  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects NULL dereference of Prefilter::OrStrings() return value",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
