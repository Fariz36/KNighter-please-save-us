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

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_TRAIT_WITH_PROGRAMSTATE(FanoutBoundsChecked, bool)

namespace {
class SAGenTestChecker : public Checker<check::BranchCondition, check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read on pack index fanout table",
                       "Memory Error")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                             CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  Cond = Cond->IgnoreParenImpCasts();
  if (ExprHasName(Cond, "short_oid->id[0]", C) &&
      ExprHasName(Cond, "p->index_map.len", C)) {
    ProgramStateRef State = C.getState();
    State = State->set<FanoutBoundsChecked>(true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                      CheckerContext &C) const {
  if (!IsLoad || !S)
    return;

  const Expr *E = dyn_cast<Expr>(S);
  if (!E)
    return;

  E = E->IgnoreParenImpCasts();
  const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E);
  if (!ASE) {
    ASE = findSpecificTypeInParents<ArraySubscriptExpr>(S, C);
  }
  if (!ASE)
    return;

  const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
  const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();

  if (!ExprHasName(Base, "level1_ofs", C) ||
      !ExprHasName(Idx, "short_oid->id[0]", C))
    return;

  ProgramStateRef State = C.getState();
  bool Checked = State->get<FanoutBoundsChecked>();
  if (Checked)
    return; // Bounds check was observed on this path.

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Out-of-bounds read on pack index fanout table: missing bounds check against p->index_map.len",
      N);
  report->addRange(ASE->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects out-of-bounds read on pack index fanout table without bounds check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
