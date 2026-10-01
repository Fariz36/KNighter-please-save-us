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
#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Map tracking whether a given output pointer parameter has been NULL-checked.
// false = unchecked, true = checked.
REGISTER_MAP_WITH_PROGRAMSTATE(NullCheckedParams, const ParmVarDecl *, bool)

namespace {

static const ParmVarDecl *getParmVarDeclFromExpr(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<ParmVarDecl>(DRE->getDecl());
  }
  return nullptr;
}

static bool isUnchecked(ProgramStateRef State, const ParmVarDecl *PVD) {
  if (!PVD)
    return false;
  const bool *Checked = State->get<NullCheckedParams>(PVD);
  return Checked && !*Checked;
}

static ProgramStateRef setChecked(ProgramStateRef State,
                                  const ParmVarDecl *PVD) {
  if (!PVD)
    return State;
  const bool *Checked = State->get<NullCheckedParams>(PVD);
  if (Checked && !*Checked) {
    return State->set<NullCheckedParams>(PVD, true);
  }
  return State;
}

class SAGenTestChecker
    : public Checker<check::BeginFunction,
                     check::BranchCondition,
                     check::PreStmt<BinaryOperator>,
                     check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL check for output pointer parameter",
                       "Null pointer dereference")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportMissingNullCheck(CheckerContext &C, const ParmVarDecl *PVD,
                              StringRef Action) const;
};

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const auto *FD = dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD)
    return;

  if (FD->getName() != "curl_easy_send" &&
      FD->getName() != "curl_easy_recv")
    return;

  bool Changed = false;
  for (const ParmVarDecl *PVD : FD->parameters()) {
    if (PVD->getName() == "n" && PVD->getType()->isPointerType()) {
      State = State->set<NullCheckedParams>(PVD, false);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  bool Changed = false;
  CondE = CondE->IgnoreParenImpCasts();

  const ParmVarDecl *PVD = nullptr;

  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      PVD = getParmVarDeclFromExpr(UO->getSubExpr());
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSIsNull = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull && !RHSIsNull) {
        PVD = getParmVarDeclFromExpr(RHS);
      } else if (RHSIsNull && !LHSIsNull) {
        PVD = getParmVarDeclFromExpr(LHS);
      }
    }
  } else {
    PVD = getParmVarDeclFromExpr(CondE);
  }

  if (PVD) {
    ProgramStateRef NewState = setChecked(State, PVD);
    if (NewState != State) {
      State = NewState;
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO,
                                    CheckerContext &C) const {
  if (BO->getOpcode() != BO_Assign)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const auto *UO = dyn_cast<UnaryOperator>(LHS);
  if (!UO || UO->getOpcode() != UO_Deref)
    return;

  const ParmVarDecl *PVD = getParmVarDeclFromExpr(UO->getSubExpr());
  if (!PVD)
    return;

  ProgramStateRef State = C.getState();
  if (isUnchecked(State, PVD)) {
    reportMissingNullCheck(C, PVD, "dereferencing it");
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *CalleeExpr = Call.getOriginExpr();
  if (!CalleeExpr || !ExprHasName(CalleeExpr, "Curl_easy_recv", C))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
    const Expr *ArgE = Call.getArgExpr(I);
    const ParmVarDecl *PVD = getParmVarDeclFromExpr(ArgE);
    if (PVD && isUnchecked(State, PVD)) {
      reportMissingNullCheck(C, PVD, "passing it to Curl_easy_recv");
      break;
    }
  }
}

void SAGenTestChecker::reportMissingNullCheck(CheckerContext &C,
                                              const ParmVarDecl *PVD,
                                              StringRef Action) const {
  if (!BT)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  std::string Msg = "Missing NULL check for output pointer parameter '" +
                    PVD->getName().str() + "' before " + Action.str();
  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  Report->addRange(PVD->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL checks for output pointer parameters before "
      "dereferencing or passing them to functions that write through them",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
