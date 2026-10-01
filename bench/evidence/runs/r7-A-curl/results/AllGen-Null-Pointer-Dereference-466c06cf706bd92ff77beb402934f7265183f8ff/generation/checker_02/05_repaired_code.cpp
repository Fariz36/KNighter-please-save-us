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

#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Set of parameter regions that have already been checked for NULL.
REGISTER_SET_WITH_PROGRAMSTATE(CheckedPtrs, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition, check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL check", "Null Pointer")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  const ParmVarDecl *getTargetParam(CheckerContext &C) const;
  bool isParamExpr(const Expr *E, const ParmVarDecl *Param) const;
  bool isParamNullCheck(const Expr *Cond, const ParmVarDecl *Param,
                        CheckerContext &C) const;
  const MemRegion *getParamRegion(const ParmVarDecl *Param,
                                  CheckerContext &C) const;
  const Expr *getDerefBase(const Stmt *S) const;
  void reportBug(const MemRegion *Region, const Stmt *S,
                 CheckerContext &C) const;
};

} // end anonymous namespace

const ParmVarDecl *SAGenTestChecker::getTargetParam(CheckerContext &C) const {
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || FD->getName() != "curl_url_dup")
    return nullptr;
  if (FD->getNumParams() == 0)
    return nullptr;

  const ParmVarDecl *Param = FD->getParamDecl(0);
  if (!Param || Param->getName() != "in")
    return nullptr;
  return Param;
}

bool SAGenTestChecker::isParamExpr(const Expr *E,
                                   const ParmVarDecl *Param) const {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return false;
  return DRE->getDecl() == Param;
}

bool SAGenTestChecker::isParamNullCheck(const Expr *Cond,
                                        const ParmVarDecl *Param,
                                        CheckerContext &C) const {
  if (!Cond)
    return false;
  Cond = Cond->IgnoreParenImpCasts();

  // if (in)
  if (isParamExpr(Cond, Param))
    return true;

  // if (!in)
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot)
      return isParamExpr(UO->getSubExpr(), Param);
  }

  // if (in == NULL) or if (in != NULL)
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (isParamExpr(LHS, Param)) {
        return RHS->isNullPointerConstant(
            C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      }
      if (isParamExpr(RHS, Param)) {
        return LHS->isNullPointerConstant(
            C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      }
    }
  }
  return false;
}

const MemRegion *SAGenTestChecker::getParamRegion(const ParmVarDecl *Param,
                                                  CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SVal LVal = State->getLValue(Param, C.getLocationContext());
  return LVal.getAsRegion();
}

const Expr *SAGenTestChecker::getDerefBase(const Stmt *S) const {
  if (const MemberExpr *ME = dyn_cast<MemberExpr>(S)) {
    if (ME->isArrow())
      return ME->getBase();
  }
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref)
      return UO->getSubExpr();
  }
  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(S)) {
    return ASE->getBase();
  }
  return nullptr;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const ParmVarDecl *Param = getTargetParam(C);
  if (!Param)
    return;

  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  if (isParamNullCheck(Cond, Param, C)) {
    ProgramStateRef State = C.getState();
    const MemRegion *ParamReg = getParamRegion(Param, C);
    if (ParamReg) {
      State = State->add<CheckedPtrs>(ParamReg);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  const ParmVarDecl *Param = getTargetParam(C);
  if (!Param)
    return;

  const Expr *Base = getDerefBase(S);
  if (!Base)
    return;

  if (!isParamExpr(Base, Param))
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *ParamReg = getParamRegion(Param, C);
  if (!ParamReg)
    return;

  if (!State->contains<CheckedPtrs>(ParamReg)) {
    reportBug(ParamReg, S, C);
  }
}

void SAGenTestChecker::reportBug(const MemRegion *Region, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  // Mark as checked to avoid duplicate reports on the same path.
  State = State->add<CheckedPtrs>(Region);

  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing NULL check for parameter 'in' before dereference", N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL check for parameter 'in' in curl_url_dup before "
      "dereference",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
