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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Casting.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/APSInt.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(ZeroedRegions, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Cleanup order violation", "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportUnlinkAfterZero(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  ProgramStateRef State = C.getState();

  if (ExprHasName(OriginExpr, "memset", C)) {
    if (Call.getNumArgs() < 2)
      return;

    const Expr *DstExpr = Call.getArgExpr(0);
    if (!DstExpr)
      return;

    const MemRegion *MR = getMemRegionFromExpr(DstExpr, C);
    if (!MR)
      return;

    const Expr *FillExpr = Call.getArgExpr(1);
    if (!FillExpr)
      return;

    llvm::APSInt FillVal;
    if (!EvaluateExprToInt(FillVal, FillExpr, C))
      return;

    if (!FillVal.isZero())
      return;

    State = State->set<ZeroedRegions>(MR, true);
    C.addTransition(State);
    return;
  }

  if (ExprHasName(OriginExpr, "Curl_peer_unlink", C)) {
    if (Call.getNumArgs() < 1)
      return;

    const Expr *ArgExpr = Call.getArgExpr(0);
    if (!ArgExpr)
      return;

    const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
    if (!MR)
      return;

    const MemRegion *R = MR;
    while (R) {
      const bool *Zeroed = State->get<ZeroedRegions>(R);
      if (Zeroed && *Zeroed) {
        reportUnlinkAfterZero(Call, C);
        return;
      }

      const auto *SR = llvm::dyn_cast<SubRegion>(R);
      if (!SR)
        break;
      R = SR->getSuperRegion();
    }
  }
}

void SAGenTestChecker::reportUnlinkAfterZero(const CallEvent &Call,
                                             CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Curl_peer_unlink after memset zeroed containing struct", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects Curl_peer_unlink after memset zeroed containing struct",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
