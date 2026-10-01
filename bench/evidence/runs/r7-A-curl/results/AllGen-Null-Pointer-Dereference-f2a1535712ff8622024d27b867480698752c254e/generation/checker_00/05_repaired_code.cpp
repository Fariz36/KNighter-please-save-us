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
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Map from parameter region to whether it has been null-checked.
// false -> not checked yet, true -> checked.
REGISTER_MAP_WITH_PROGRAMSTATE(NullCheckMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker
    : public Checker<check::BeginFunction,
                     check::BranchCondition,
                     check::PreStmt<BinaryOperator>,
                     check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL check for output parameter",
                       "API Misuse")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportMissingNullCheck(const Stmt *S, CheckerContext &C) const;
};

} // end anonymous namespace

static const FunctionDecl *getCurrentFunction(CheckerContext &C) {
  const Decl *D = C.getLocationContext()->getDecl();
  return dyn_cast_or_null<FunctionDecl>(D);
}

static const ParmVarDecl *getOutputParam(const FunctionDecl *FD) {
  if (!FD)
    return nullptr;
  if (FD->getNumParams() <= 3)
    return nullptr;
  return FD->getParamDecl(3);
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;

  StringRef Name = FD->getName();
  if (Name != "curl_easy_send" && Name != "curl_easy_recv")
    return;

  const ParmVarDecl *Parm = getOutputParam(FD);
  if (!Parm)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *Region = State->getRegion(Parm, C.getLocationContext());
  if (!Region)
    return;

  Region = Region->getBaseRegion();
  State = State->set<NullCheckMap>(Region, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD)
    return;

  StringRef Name = FD->getName();
  if (Name != "curl_easy_send" && Name != "curl_easy_recv")
    return;

  const ParmVarDecl *Parm = getOutputParam(FD);
  if (!Parm)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;
  CondE = CondE->IgnoreParenImpCasts();

  bool isNullCheck = false;

  // Case: !n
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(SubE)) {
        if (DRE->getDecl() == Parm)
          isNullCheck = true;
      }
    }
  }
  // Case: n == NULL or n != NULL
  else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      const DeclRefExpr *DRE = nullptr;
      const Expr *Other = nullptr;

      if (const auto *L = dyn_cast<DeclRefExpr>(LHS)) {
        if (L->getDecl() == Parm) {
          DRE = L;
          Other = RHS;
        }
      } else if (const auto *R = dyn_cast<DeclRefExpr>(RHS)) {
        if (R->getDecl() == Parm) {
          DRE = R;
          Other = LHS;
        }
      }

      if (DRE && Other &&
          Other->isNullPointerConstant(C.getASTContext(),
                                       Expr::NPC_ValueDependentIsNull)) {
        isNullCheck = true;
      }
    }
  }

  if (!isNullCheck)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *Region = State->getRegion(Parm, C.getLocationContext());
  if (!Region)
    return;

  Region = Region->getBaseRegion();
  State = State->set<NullCheckMap>(Region, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO,
                                    CheckerContext &C) const {
  if (BO->getOpcode() != BO_Assign)
    return;

  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD || FD->getName() != "curl_easy_send")
    return;

  const ParmVarDecl *Parm = getOutputParam(FD);
  if (!Parm)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const auto *UO = dyn_cast<UnaryOperator>(LHS);
  if (!UO || UO->getOpcode() != UO_Deref)
    return;

  const Expr *SubE = UO->getSubExpr()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(SubE);
  if (!DRE || DRE->getDecl() != Parm)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *Region = State->getRegion(Parm, C.getLocationContext());
  if (!Region)
    return;

  Region = Region->getBaseRegion();
  const bool *Checked = State->get<NullCheckMap>(Region);
  if (Checked && *Checked == false) {
    reportMissingNullCheck(BO, C);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunction(C);
  if (!FD || FD->getName() != "curl_easy_recv")
    return;

  const ParmVarDecl *Parm = getOutputParam(FD);
  if (!Parm)
    return;

  const Expr *CalleeE = Call.getOriginExpr();
  if (!CalleeE || !ExprHasName(CalleeE, "Curl_easy_recv", C))
    return;

  if (Call.getNumArgs() <= 3)
    return;

  const Expr *Arg3 = Call.getArgExpr(3);
  if (!Arg3)
    return;

  const auto *DRE = dyn_cast<DeclRefExpr>(Arg3->IgnoreParenImpCasts());
  if (!DRE || DRE->getDecl() != Parm)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *Region = State->getRegion(Parm, C.getLocationContext());
  if (!Region)
    return;

  Region = Region->getBaseRegion();
  const bool *Checked = State->get<NullCheckMap>(Region);
  if (Checked && *Checked == false) {
    reportMissingNullCheck(Call.getOriginExpr(), C);
  }
}

void SAGenTestChecker::reportMissingNullCheck(const Stmt *S,
                                              CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing NULL check for output parameter 'n' before dereference", N);

  if (S)
    Report->addRange(S->getSourceRange());

  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL check for output parameter 'n' in curl_easy_send/recv",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
