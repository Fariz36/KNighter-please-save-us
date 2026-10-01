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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(CheckedNSet, const VarDecl *)

namespace {

class SAGenTestChecker
    : public Checker<check::BranchCondition,
                     check::PreStmt<UnaryOperator>,
                     check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL check", "API Misuse")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

static bool isTargetFunction(const FunctionDecl *FD) {
  if (!FD)
    return false;
  StringRef Name = FD->getName();
  return Name == "curl_easy_send" || Name == "curl_easy_recv";
}

static const VarDecl *getNParam(const FunctionDecl *FD) {
  if (!FD)
    return nullptr;
  for (const ParmVarDecl *P : FD->parameters()) {
    if (P->getName() == "n")
      return P;
  }
  return nullptr;
}

static bool isNVarRef(const Expr *E, const VarDecl *NVar) {
  if (!E || !NVar)
    return false;
  E = E->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
  return DRE && DRE->getDecl() == NVar;
}

static bool isNullCheck(const Expr *E, const VarDecl *NVar) {
  if (!E || !NVar)
    return false;

  E = E->IgnoreParenImpCasts();

  if (isNVarRef(E, NVar))
    return true;

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot)
      return isNVarRef(UO->getSubExpr(), NVar);
  }

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      ASTContext &AC = NVar->getASTContext();

      if (isNVarRef(LHS, NVar) &&
          RHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull))
        return true;
      if (isNVarRef(RHS, NVar) &&
          LHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull))
        return true;
    }
  }

  return false;
}

static const VarDecl *getCurrentNParam(CheckerContext &C) {
  const FunctionDecl *FD =
      dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!isTargetFunction(FD))
    return nullptr;
  return getNParam(FD);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const VarDecl *NVar = getCurrentNParam(C);
  if (!NVar)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  if (!isNullCheck(CondE, NVar))
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<CheckedNSet>(NVar))
    C.addTransition(State->add<CheckedNSet>(NVar));
}

void SAGenTestChecker::checkPreStmt(const UnaryOperator *UO,
                                    CheckerContext &C) const {
  if (UO->getOpcode() != UO_Deref)
    return;

  const VarDecl *NVar = getCurrentNParam(C);
  if (!NVar)
    return;

  const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub);
  if (!DRE || DRE->getDecl() != NVar)
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<CheckedNSet>(NVar))
    return;

  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Missing NULL check for 'n' before dereference", N);
    R->addRange(UO->getSourceRange());
    C.emitReport(std::move(R));
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const FunctionDecl *CalleeFD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!CalleeFD || CalleeFD->getName() != "Curl_easy_recv")
    return;

  const VarDecl *NVar = getCurrentNParam(C);
  if (!NVar)
    return;

  if (Call.getNumArgs() < 4)
    return;

  const Expr *Arg = Call.getArgExpr(3);
  if (!Arg)
    return;

  Arg = Arg->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Arg);
  if (!DRE || DRE->getDecl() != NVar)
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<CheckedNSet>(NVar))
    return;

  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto R = std::make_unique<PathSensitiveBugReport>(
        *BT, "Missing NULL check for 'n' before forwarding", N);
    R->addRange(Call.getSourceRange());
    C.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL checks for 'n' in curl_easy_send/recv",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
