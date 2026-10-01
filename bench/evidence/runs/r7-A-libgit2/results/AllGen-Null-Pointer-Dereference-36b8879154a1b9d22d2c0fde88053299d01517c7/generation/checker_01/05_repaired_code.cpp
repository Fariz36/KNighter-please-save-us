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
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(UncheckedHunkRegions, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::BranchCondition,
                                        check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked NULL Return", "Logic Error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  bool isFunctionNamed(const CallEvent &Call, StringRef Name,
                       CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isFunctionNamed(const CallEvent &Call, StringRef Name,
                                       CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  return OriginExpr && ExprHasName(OriginExpr, Name, C);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isFunctionNamed(Call, "hunk_from_entry", C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  const MemRegion *MR = Ret.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  State = State->add<UncheckedHunkRegions>(MR);
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

  CondE = CondE->IgnoreParenCasts();

  const Expr *PtrExpr = nullptr;

  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      PtrExpr = UO->getSubExpr()->IgnoreParenCasts();
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
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
    PtrExpr = CondE;
  }

  if (PtrExpr) {
    SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
    if (const MemRegion *MR = PtrVal.getAsRegion()) {
      MR = MR->getBaseRegion();
      if (State->contains<UncheckedHunkRegions>(MR)) {
        State = State->remove<UncheckedHunkRegions>(MR);
      }
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isFunctionNamed(Call, "git_vector_insert", C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  SVal Arg = Call.getArgSVal(1);
  const MemRegion *MR = Arg.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<UncheckedHunkRegions>(MR))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unchecked NULL return from hunk_from_entry() used in git_vector_insert",
      N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked NULL return from hunk_from_entry() used in "
      "git_vector_insert",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
