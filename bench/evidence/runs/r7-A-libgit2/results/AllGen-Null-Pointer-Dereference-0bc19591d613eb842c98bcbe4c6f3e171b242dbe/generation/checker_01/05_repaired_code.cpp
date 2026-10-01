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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::PreStmt<ReturnStmt>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Early success return with NULL out-parameter",
                       "Null Dereference")) {}

  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS,
                                    CheckerContext &C) const {
  if (!RS)
    return;

  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return;

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(LCtx->getDecl());
  if (!FD || FD->getName() != "load_known_hosts")
    return;

  if (FD->getNumParams() < 1)
    return;

  const ParmVarDecl *HostsParam = FD->getParamDecl(0);
  if (!HostsParam)
    return;

  const Expr *RetExpr = RS->getRetValue();
  if (!RetExpr)
    return;

  ProgramStateRef State = C.getState();

  // Check that the function is returning success (0).
  SVal RetVal = State->getSVal(RetExpr, LCtx);
  auto RetValD = RetVal.getAs<DefinedOrUnknownSVal>();
  if (!RetValD)
    return;
  ProgramStateRef RetTrue = State->assume(*RetValD, true);
  ProgramStateRef RetFalse = State->assume(*RetValD, false);
  if (RetTrue || !RetFalse)
    return;

  // Get the first parameter `hosts`, which is a pointer-to-pointer.
  const MemRegion *HostsReg = State->getRegion(HostsParam, LCtx);
  if (!HostsReg)
    return;

  SVal HostsPtr = State->getSVal(HostsReg);

  // It must be a location so that we can dereference it.
  auto HostsLoc = HostsPtr.getAs<Loc>();
  if (!HostsLoc)
    return;

  // Load the value of *hosts.
  const MemRegion *OutRegion = HostsLoc->getAsRegion();
  if (!OutRegion)
    return;

  SVal OutVal = State->getSVal(OutRegion);

  // Report if *hosts is NULL while the function reports success.
  auto OutValD = OutVal.getAs<DefinedOrUnknownSVal>();
  if (!OutValD)
    return;
  ProgramStateRef OutNonNull = State->assume(*OutValD, true);
  ProgramStateRef OutNull = State->assume(*OutValD, false);
  if (OutNonNull || !OutNull)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "load_known_hosts may return success with NULL *hosts", N);
  Report->addRange(RS->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects success returns from load_known_hosts with a NULL out-parameter",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
