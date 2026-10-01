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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/OperationKinds.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks which parameter regions have already been NULL-checked.
REGISTER_SET_WITH_PROGRAMSTATE(CheckedParams, const MemRegion *)

namespace {

class SAGenTestChecker
    : public Checker<check::BranchCondition,
                     check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "NULL pointer dereference", "Null Dereference")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;

private:
  bool isCurlUrlDup(CheckerContext &C) const;
  bool isTargetParam(const MemRegion *R) const;
  const DeclRefExpr *getInParamDRE(const Expr *E) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isCurlUrlDup(CheckerContext &C) const {
  const Decl *D = C.getLocationContext()->getDecl();
  if (const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D))
    return FD->getNameAsString() == "curl_url_dup";
  return false;
}

bool SAGenTestChecker::isTargetParam(const MemRegion *R) const {
  if (!R)
    return false;

  R = R->getBaseRegion();
  if (!R)
    return false;

  const VarRegion *VR = dyn_cast<VarRegion>(R);
  if (!VR)
    return false;

  const VarDecl *VD = VR->getDecl();
  if (const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(VD))
    return PVD->getNameAsString() == "in";

  return false;
}

const DeclRefExpr *SAGenTestChecker::getInParamDRE(const Expr *E) const {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return nullptr;

  const ValueDecl *VD = DRE->getDecl();
  if (const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(VD)) {
    if (PVD->getNameAsString() == "in")
      return DRE;
  }

  return nullptr;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!isCurlUrlDup(C))
    return;

  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  Cond = Cond->IgnoreParenImpCasts();
  const DeclRefExpr *InDRE = nullptr;

  // Pattern: if (!in)
  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      InDRE = getInParamDRE(UO->getSubExpr());
    }
  }
  // Pattern: if (in == NULL) / if (in != NULL) / if (NULL == in) / if (NULL != in)
  else if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();

      const DeclRefExpr *LHSIn = getInParamDRE(LHS);
      const DeclRefExpr *RHSIn = getInParamDRE(RHS);

      bool LHSNull = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSNull = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);

      if (LHSIn && RHSNull)
        InDRE = LHSIn;
      else if (RHSIn && LHSNull)
        InDRE = RHSIn;
    }
  }
  // Pattern: if (in)
  else {
    InDRE = getInParamDRE(Cond);
  }

  if (!InDRE)
    return;

  ProgramStateRef State = C.getState();
  const VarDecl *VD = dyn_cast<VarDecl>(InDRE->getDecl());
  if (!VD)
    return;

  // Get the VarRegion of the parameter "in" itself.
  SVal LVal = State->getLValue(VD, C.getLocationContext());
  const MemRegion *Region = LVal.getAsRegion();
  if (!Region)
    return;

  Region = Region->getBaseRegion();
  if (!Region)
    return;

  State = State->add<CheckedParams>(Region);
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!isCurlUrlDup(C))
    return;

  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  const MemRegion *Base = R->getBaseRegion();
  if (!Base)
    return;

  if (!isTargetParam(Base))
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<CheckedParams>(Base))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "NULL pointer dereference: 'in' is not checked for NULL before use.", N);

  if (S)
    Report->addRange(S->getSourceRange());

  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL check on 'in' in curl_url_dup before dereference",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
