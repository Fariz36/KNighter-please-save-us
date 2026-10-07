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
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Store.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(OutputPtrCheckedMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::BeginFunction,
                                        check::BranchCondition,
                                        check::Bind,
                                        check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Output Pointer Null Check",
                       "Null Pointer Dereference")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const Stmt *S, CheckerContext &C, StringRef Msg) const;
  static bool isParamOfCurrentFunction(const ParmVarDecl *PVD, CheckerContext &C);
  static const VarRegion *getParamVarRegion(const ParmVarDecl *PVD, CheckerContext &C);
};

} // end anonymous namespace

bool SAGenTestChecker::isParamOfCurrentFunction(const ParmVarDecl *PVD,
                                                CheckerContext &C) {
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return false;
  for (const ParmVarDecl *P : FD->parameters()) {
    if (P == PVD)
      return true;
  }
  return false;
}

const VarRegion *SAGenTestChecker::getParamVarRegion(const ParmVarDecl *PVD,
                                                     CheckerContext &C) {
  if (!isParamOfCurrentFunction(PVD, C))
    return nullptr;
  return C.getSValBuilder().getRegionManager().getVarRegion(
      PVD, C.getLocationContext());
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return;

  // Focus on public API functions: skip static functions and internal writers.
  if (FD->isStatic())
    return;
  if (knighter::declIsRole(FD, "internal_writer"))
    return;

  ProgramStateRef State = C.getState();
  for (const ParmVarDecl *PVD : FD->parameters()) {
    if (PVD->getType()->isPointerType()) {
      const VarRegion *VR = C.getSValBuilder().getRegionManager().getVarRegion(
          PVD, C.getLocationContext());
      if (VR)
        State = State->set<OutputPtrCheckedMap>(VR, false);
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }
  CondE = CondE->IgnoreParenImpCasts();

  auto markDRE = [&](const Expr *E) {
    E = E->IgnoreParenImpCasts();
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
    if (!DRE)
      return;
    const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
    if (!PVD)
      return;
    const VarRegion *VR = getParamVarRegion(PVD, C);
    if (!VR)
      return;
    // Only update if the region is already tracked.
    if (State->get<OutputPtrCheckedMap>(VR)) {
      State = State->set<OutputPtrCheckedMap>(VR, true);
    }
  };

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      markDRE(UO->getSubExpr());
    }
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(),
                                                 Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(),
                                                 Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && !RHSIsNull)
        markDRE(RHS);
      else if (RHSIsNull && !LHSIsNull)
        markDRE(LHS);
    }
  } else {
    markDRE(CondE);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || BO->getOpcode() != BO_Assign)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const UnaryOperator *UO = dyn_cast<UnaryOperator>(LHS);
  if (!UO || UO->getOpcode() != UO_Deref)
    return;

  const Expr *SubE = UO->getSubExpr()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(SubE);
  if (!DRE)
    return;

  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD)
    return;

  const VarRegion *VR = getParamVarRegion(PVD, C);
  if (!VR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<OutputPtrCheckedMap>(VR);
  if (Checked && *Checked == false) {
    reportBug(S, C,
              "Output pointer parameter may be NULL and is dereferenced before being checked");
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "internal_writer"))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    const Expr *ArgExpr = Call.getArgExpr(I);
    if (!ArgExpr)
      continue;
    ArgExpr = ArgExpr->IgnoreParenImpCasts();
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(ArgExpr);
    if (!DRE)
      continue;
    const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
    if (!PVD)
      continue;

    const VarRegion *VR = getParamVarRegion(PVD, C);
    if (!VR)
      continue;

    const bool *Checked = State->get<OutputPtrCheckedMap>(VR);
    if (Checked && *Checked == false) {
      reportBug(ArgExpr, C,
                "Output pointer parameter may be NULL and is passed to an internal writer before being checked");
      return; // Report once per call.
    }
  }
}

void SAGenTestChecker::reportBug(const Stmt *S, CheckerContext &C,
                                 StringRef Msg) const {
  if (!BT)
    return;
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
      "Detects nullable output pointer parameters used before NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "internal_writer": {
    "names": ["Curl_easy_recv"],
    "description": "writes through one or more of its pointer arguments; those arguments must be non-null"
  }
}
*/
