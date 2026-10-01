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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(GitStrNeedsDisposeMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker
    : public Checker<eval::Call,
                     check::PostCall,
                     check::PreStmt<ReturnStmt>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory leak", "Memory Management")) {}

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;

private:
  void reportLeak(const ReturnStmt *RS, CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::evalCall(const CallEvent &Call,
                                CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr ||
      !ExprHasName(OriginExpr, "git_fs_path_prettify_dir", C))
    return false;

  const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
  if (!CE || CE->getNumArgs() < 1)
    return false;

  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0)
    return false;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
  if (!MR)
    return false;

  MR = MR->getBaseRegion();
  if (!MR)
    return false;

  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR || !VR->getDecl() || !VR->getDecl()->hasLocalStorage())
    return false;

  SValBuilder &SVB = C.getSValBuilder();
  SVal RetVal = SVB.makeIntVal(0, C.getASTContext().IntTy);
  State = State->BindExpr(CE, C.getLocationContext(), RetVal);
  if (!State)
    return false;

  State = State->set<GitStrNeedsDisposeMap>(MR, true);
  C.addTransition(State);
  return true;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  if (!ExprHasName(OriginExpr, "git_str_dispose", C) &&
      !ExprHasName(OriginExpr, "git_str_detach", C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  if (State->get<GitStrNeedsDisposeMap>(MR)) {
    State = State->remove<GitStrNeedsDisposeMap>(MR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const auto &Map = State->get<GitStrNeedsDisposeMap>();
  if (Map.isEmpty())
    return;

  reportLeak(RS, C);
}

void SAGenTestChecker::reportLeak(const ReturnStmt *RS,
                                  CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Memory leak: git_str buffer not disposed", N);
  report->addRange(RS->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing git_str_dispose/git_str_detach before return",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
