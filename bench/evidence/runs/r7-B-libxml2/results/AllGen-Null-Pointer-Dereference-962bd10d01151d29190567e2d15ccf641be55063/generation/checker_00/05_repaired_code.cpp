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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Track whether the `capacity` parameter of xmlGrowArray has been NULL-checked.
REGISTER_TRAIT_WITH_PROGRAMSTATE(CapacityChecked, bool)

namespace {

class SAGenTestChecker
    : public Checker<check::BeginFunction,
                     check::BranchCondition,
                     check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Null Pointer Dereference",
                       "Dereference of NULL pointer parameter")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
};

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const FunctionDecl *FD =
      dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD || FD->getName() != "xmlGrowArray")
    return;

  ProgramStateRef State = C.getState();
  State = State->set<CapacityChecked>(false);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const FunctionDecl *FD =
      dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD || FD->getName() != "xmlGrowArray")
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  if (ExprHasName(CondE, "capacity", C)) {
    ProgramStateRef State = C.getState();
    State = State->set<CapacityChecked>(true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  const FunctionDecl *FD =
      dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD || FD->getName() != "xmlGrowArray")
    return;

  const UnaryOperator *UO = dyn_cast<UnaryOperator>(S);
  if (!UO || UO->getOpcode() != UO_Deref)
    return;

  const Expr *Sub = UO->getSubExpr()->IgnoreImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub);
  if (!DRE)
    return;

  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD || PVD->getName() != "capacity")
    return;

  ProgramStateRef State = C.getState();
  if (State->get<CapacityChecked>())
    return;

  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Dereference of NULL pointer parameter 'capacity' without NULL check",
        N);
    Report->addRange(S->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of NULL pointer parameter 'capacity' without NULL "
      "check in xmlGrowArray",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
