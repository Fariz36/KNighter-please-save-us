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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ASTContext.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(CheckedPtrSet, const MemRegion *)

namespace {

static bool isTargetFunction(const FunctionDecl *FD) {
  if (!FD)
    return false;
  const IdentifierInfo *II = FD->getIdentifier();
  if (!II)
    return false;
  StringRef Name = II->getName();
  return Name == "curl_easy_send" || Name == "curl_easy_recv";
}

static bool isTargetParam(const VarDecl *VD) {
  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(VD);
  if (!PVD)
    return false;
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(PVD->getDeclContext());
  if (!FD || !isTargetFunction(FD))
    return false;
  return FD->getNumParams() > 3 && FD->getParamDecl(3) == PVD;
}

static const MemRegion *getTargetParamRegion(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  const Expr *E2 = E->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E2);
  if (!DRE)
    return nullptr;
  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD || !isTargetParam(VD))
    return nullptr;
  return C.getSValBuilder().getRegionManager().getVarRegion(
      VD, C.getLocationContext());
}

class SAGenTestChecker : public Checker<
    check::BranchCondition,
    check::Bind,
    check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL check for pointer argument",
                       "Null Pointer")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportMissingCheck(const Stmt *S, CheckerContext &C,
                          const char *Msg) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;
  Cond = Cond->IgnoreParenCasts();

  const Expr *PtrExpr = nullptr;
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      PtrExpr = UO->getSubExpr();
    }
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && !RHSIsNull)
        PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrExpr = LHS;
    }
  } else {
    PtrExpr = Cond;
  }

  if (!PtrExpr)
    return;

  const MemRegion *MR = getTargetParamRegion(PtrExpr, C);
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<CheckedPtrSet>(MR);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  const Expr *PtrExpr = nullptr;
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp()) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(LHS)) {
        if (UO->getOpcode() == UO_Deref)
          PtrExpr = UO->getSubExpr();
      }
    }
  } else if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_Deref)
      PtrExpr = UO->getSubExpr();
  }

  if (!PtrExpr)
    return;

  const MemRegion *MR = getTargetParamRegion(PtrExpr, C);
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<CheckedPtrSet>(MR)) {
    reportMissingCheck(S, C,
        "Missing NULL check for argument 'n' before write.");
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;
    const Expr *ArgE = Call.getArgExpr(Idx);
    if (!ArgE)
      continue;
    const MemRegion *MR = getTargetParamRegion(ArgE, C);
    if (!MR)
      continue;
    if (!State->contains<CheckedPtrSet>(MR)) {
      reportMissingCheck(Call.getOriginExpr(), C,
          "Missing NULL check for argument 'n' before call that dereferences it.");
      return;
    }
  }
}

void SAGenTestChecker::reportMissingCheck(const Stmt *S, CheckerContext &C,
                                          const char *Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL checks for pointer argument 'n' in curl_easy_send/recv",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
