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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(CheckedParams, const ParmVarDecl *, bool)

namespace {

static const ParmVarDecl *getParamFromExpr(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
      if (PVD->getType()->isPointerType())
        return PVD;
    }
  }
  return nullptr;
}

static const ParmVarDecl *getDerefedParam(const Stmt *S) {
  if (!S)
    return nullptr;
  if (const auto *E = dyn_cast<Expr>(S)) {
    S = E->IgnoreParenImpCasts();
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref) {
      return getParamFromExpr(UO->getSubExpr());
    }
  } else if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(S)) {
    return getParamFromExpr(ASE->getBase());
  } else if (const auto *ME = dyn_cast<MemberExpr>(S)) {
    if (ME->isArrow())
      return getParamFromExpr(ME->getBase());
  } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp())
      return getDerefedParam(BO->getLHS());
  }
  return nullptr;
}

static const ParmVarDecl *getNullCheckedParam(const Expr *Cond, ASTContext &Ctx) {
  if (!Cond)
    return nullptr;
  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot)
      return getParamFromExpr(UO->getSubExpr());
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LNull = LHS->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
      bool RNull = RHS->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
      if (LNull && !RNull)
        return getParamFromExpr(RHS);
      if (RNull && !LNull)
        return getParamFromExpr(LHS);
    }
  }

  return getParamFromExpr(Cond);
}

class SAGenTestChecker : public Checker<check::BranchCondition, check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "NULL pointer parameter dereferenced before NULL check",
                       "Null Pointer Dereference")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return;

  const ParmVarDecl *Param = getNullCheckedParam(CondE, C.getASTContext());
  if (!Param)
    return;

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<CheckedParams>(Param);
  if (Checked && *Checked)
    return;

  State = State->set<CheckedParams>(Param, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  (void)Loc;
  (void)IsLoad;

  const LocationContext *LC = C.getLocationContext();
  if (!LC)
    return;

  const Decl *D = LC->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return;
  if (!knighter::declIsRole(FD, "reallocator"))
    return;

  const ParmVarDecl *Param = getDerefedParam(S);
  if (!Param)
    return;

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<CheckedParams>(Param);
  if (Checked && *Checked)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "NULL pointer parameter dereferenced before NULL check", N);
  if (S)
    Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));

  State = State->set<CheckedParams>(Param, true);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects NULL pointer parameter dereference before NULL check in reallocator functions",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "reallocator": {
    "names": ["xmlGrowArray", "xmlRealloc"],
    "description": "resize/grow an existing allocation and return the new pointer, possibly NULL on failure"
  }
}
*/
