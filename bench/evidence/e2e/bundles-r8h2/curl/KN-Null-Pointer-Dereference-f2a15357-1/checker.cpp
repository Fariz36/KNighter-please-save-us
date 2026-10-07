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
#include "clang/AST/OperationKinds.h"
#include "clang/AST/Stmt.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(OutParamCheckedMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::BeginFunction,
                                        check::BranchCondition,
                                        check::PreCall,
                                        check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing null check for out parameter",
                       "API misuse")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  const ParmVarDecl *getOutParamFromExpr(const Expr *E, CheckerContext &C) const;
  const ParmVarDecl *getOutParamFromNullCheck(const Expr *E,
                                              CheckerContext &C) const;
  bool isCurrentFunctionParm(const ParmVarDecl *PVD, CheckerContext &C) const;
  void reportMissingNullCheck(CheckerContext &C, const Stmt *UseStmt,
                              const ParmVarDecl *PVD) const;
};

bool SAGenTestChecker::isCurrentFunctionParm(const ParmVarDecl *PVD,
                                             CheckerContext &C) const {
  if (!PVD)
    return false;

  AnalysisDeclContext *ADC = C.getCurrentAnalysisDeclContext();
  if (!ADC)
    return false;

  const Decl *D = ADC->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return false;

  return PVD->getDeclContext() == static_cast<const DeclContext *>(FD);
}

const ParmVarDecl *SAGenTestChecker::getOutParamFromExpr(const Expr *E,
                                                         CheckerContext &C) const {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();

  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return nullptr;

  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD)
    return nullptr;

  if (!knighter::declIsRole(PVD, "out_param"))
    return nullptr;

  if (!isCurrentFunctionParm(PVD, C))
    return nullptr;

  return PVD;
}

const ParmVarDecl *
SAGenTestChecker::getOutParamFromNullCheck(const Expr *E,
                                           CheckerContext &C) const {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();

  // if (!n)
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot)
      return getOutParamFromExpr(UO->getSubExpr(), C);
  }

  // if (n == NULL), if (n != NULL), if (NULL == n), if (NULL != n)
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();

      const Expr *LHSNoCast = LHS->IgnoreParenImpCasts();
      const Expr *RHSNoCast = RHS->IgnoreParenImpCasts();

      bool LHSIsNull = LHSNoCast->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHSNoCast->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull && !RHSIsNull)
        return getOutParamFromExpr(RHS, C);
      if (RHSIsNull && !LHSIsNull)
        return getOutParamFromExpr(LHS, C);
    }
  }

  // if (n)
  return getOutParamFromExpr(E, C);
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  AnalysisDeclContext *ADC = C.getCurrentAnalysisDeclContext();
  if (!ADC)
    return;

  const Decl *D = ADC->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return;

  if (!knighter::declIsRole(FD, "api_entry_point"))
    return;

  ProgramStateRef State = C.getState();
  if (!State)
    return;

  bool Changed = false;

  for (const ParmVarDecl *PVD : FD->parameters()) {
    if (!knighter::declIsRole(PVD, "out_param"))
      continue;

    const MemRegion *R = State->getRegion(PVD, C.getLocationContext());
    if (!R)
      continue;

    State = State->set<OutParamCheckedMap>(R, false);
    Changed = true;
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  const ParmVarDecl *PVD = getOutParamFromNullCheck(Cond, C);
  if (!PVD)
    return;

  ProgramStateRef State = C.getState();
  if (!State)
    return;

  const MemRegion *R = State->getRegion(PVD, C.getLocationContext());
  if (!R)
    return;

  const bool *Checked = State->get<OutParamCheckedMap>(R);
  if (Checked && !*Checked) {
    State = State->set<OutParamCheckedMap>(R, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "out_param_writer"))
    return;

  const CallExpr *CE = dyn_cast<CallExpr>(Call.getOriginExpr());
  if (!CE)
    return;

  ProgramStateRef State = C.getState();
  if (!State)
    return;

  for (unsigned I = 0, E = CE->getNumArgs(); I != E; ++I) {
    const Expr *Arg = CE->getArg(I);
    const ParmVarDecl *PVD = getOutParamFromExpr(Arg, C);
    if (!PVD)
      continue;

    const MemRegion *R = State->getRegion(PVD, C.getLocationContext());
    if (!R)
      continue;

    const bool *Checked = State->get<OutParamCheckedMap>(R);
    if (Checked && !*Checked)
      reportMissingNullCheck(C, Arg, PVD);
  }
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

  const ParmVarDecl *PVD = getOutParamFromExpr(UO->getSubExpr(), C);
  if (!PVD)
    return;

  ProgramStateRef State = C.getState();
  if (!State)
    return;

  const MemRegion *R = State->getRegion(PVD, C.getLocationContext());
  if (!R)
    return;

  const bool *Checked = State->get<OutParamCheckedMap>(R);
  if (Checked && !*Checked)
    reportMissingNullCheck(C, S, PVD);
}

void SAGenTestChecker::reportMissingNullCheck(CheckerContext &C,
                                              const Stmt *UseStmt,
                                              const ParmVarDecl *PVD) const {
  if (!BT)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing null check for out parameter before use", N);

  if (UseStmt)
    Report->addRange(UseStmt->getSourceRange());

  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing null checks for out parameters before use",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "api_entry_point": {"names": ["curl_easy_recv", "curl_easy_send"], "description": "public API entry point that may accept an out parameter"},
  "out_param": {"names": ["n"], "description": "pointer parameter used as an output parameter"},
  "out_param_writer": {"names": ["Curl_easy_recv"], "description": "function that writes through a pointer argument"}
}
*/
