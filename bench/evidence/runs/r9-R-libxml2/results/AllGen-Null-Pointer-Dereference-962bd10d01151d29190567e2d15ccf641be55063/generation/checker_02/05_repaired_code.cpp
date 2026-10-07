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

// Program state set to keep track of pointer parameters that have been checked against NULL.
REGISTER_SET_WITH_PROGRAMSTATE(CheckedParams, const VarDecl *)

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition, check::Location> {
   mutable std::unique_ptr<BugType> BT;

public:
   SAGenTestChecker() : BT(new BugType(this, "NULL Pointer Dereference", "Null Dereference")) {}

   void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
   void checkLocation(SVal Loc, bool isLoad, const Stmt *S, CheckerContext &C) const;

private:
   bool isPointerParamOfFunction(const VarDecl *VD, const FunctionDecl *FD) const;
   const VarDecl *getVarDeclFromExpr(const Expr *E) const;
   void reportDeref(const Stmt *S, const VarDecl *VD, CheckerContext &C) const;
};

bool SAGenTestChecker::isPointerParamOfFunction(const VarDecl *VD, const FunctionDecl *FD) const {
  if (!VD->getType()->isPointerType())
    return false;
  for (const ParmVarDecl *P : FD->parameters()) {
    if (P == VD)
      return true;
  }
  return false;
}

const VarDecl *SAGenTestChecker::getVarDeclFromExpr(const Expr *E) const {
  E = E->IgnoreParenCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<VarDecl>(DRE->getDecl());
  }
  return nullptr;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD || !knighter::declIsRole(FD, "allocator"))
    return;

  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  Cond = Cond->IgnoreParenCasts();
  const Expr *PtrExpr = nullptr;

  // Handle !p
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      PtrExpr = UO->getSubExpr()->IgnoreParenCasts();
    }
  }
  // Handle p == NULL, p != NULL, NULL == p, NULL != p
  else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && !RHSIsNull)
        PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrExpr = LHS;
    }
  }
  // Handle simple p (truthiness check)
  else {
    PtrExpr = Cond;
  }

  if (!PtrExpr)
    return;

  const VarDecl *VD = getVarDeclFromExpr(PtrExpr);
  if (!VD)
    return;

  if (!isPointerParamOfFunction(VD, FD))
    return;

  ProgramStateRef State = C.getState();
  State = State->add<CheckedParams>(VD);
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool isLoad, const Stmt *S, CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD || !knighter::declIsRole(FD, "allocator"))
    return;

  const Expr *BaseExpr = nullptr;

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref) {
      BaseExpr = UO->getSubExpr();
    }
  } else if (const MemberExpr *ME = dyn_cast<MemberExpr>(S)) {
    if (ME->isArrow()) {
      BaseExpr = ME->getBase();
    }
  } else if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(S)) {
    BaseExpr = ASE->getBase();
  }

  if (!BaseExpr)
    return;

  const VarDecl *VD = getVarDeclFromExpr(BaseExpr);
  if (!VD)
    return;

  if (!isPointerParamOfFunction(VD, FD))
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<CheckedParams>(VD))
    return;

  reportDeref(S, VD, C);
}

void SAGenTestChecker::reportDeref(const Stmt *S, const VarDecl *VD, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Pointer parameter dereferenced before NULL check", N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));

  // Mark as checked to avoid multiple warnings for the same parameter on the same path.
  ProgramStateRef State = C.getState();
  State = State->add<CheckedParams>(VD);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereferences of pointer parameters before NULL checks in allocator functions",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {"names": ["xmlGrowArray"], "description": "allocates or grows memory; may return NULL"},
  "reallocator": {"names": ["xmlRealloc"], "description": "reallocates memory; returns new pointer or NULL"}
}
*/
