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
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Map from a base memory region to whether it has been zeroed.
REGISTER_MAP_WITH_PROGRAMSTATE(ZeroedRegionMap, const MemRegion *, bool)

namespace {

static bool isCallTo(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, Name, C);
}

static const MemRegion *getPointeeRegion(SVal Ptr, CheckerContext &C) {
  if (const MemRegion *R = Ptr.getAsRegion())
    return R;
  if (SymbolRef Sym = Ptr.getAsSymbol())
    return C.getSValBuilder().getRegionManager().getSymbolicRegion(Sym);
  return nullptr;
}

static const MemRegion *getBaseRegionFromSVal(SVal V, CheckerContext &C) {
  const MemRegion *R = getPointeeRegion(V, C);
  if (!R)
    return nullptr;
  return R->getBaseRegion();
}

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unlink after zeroing leaks peer",
                       "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportUnlinkAfterZero(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Model memset(ptr, 0, size) as zeroing the base region.
  if (isCallTo(Call, "memset", C)) {
    const Expr *Arg1 = Call.getArgExpr(1);
    if (!Arg1)
      return;

    llvm::APSInt EvalRes;
    if (!EvaluateExprToInt(EvalRes, Arg1, C) || !EvalRes.isZero())
      return;

    SVal Arg0 = Call.getArgSVal(0);
    const MemRegion *Base = getBaseRegionFromSVal(Arg0, C);
    if (!Base)
      return;

    State = State->set<ZeroedRegionMap>(Base, true);
    C.addTransition(State);
    return;
  }

  // Model cf_h2_proxy_ctx_clear(ctx) as zeroing ctx.
  if (isCallTo(Call, "cf_h2_proxy_ctx_clear", C)) {
    SVal Arg0 = Call.getArgSVal(0);
    const MemRegion *Base = getBaseRegionFromSVal(Arg0, C);
    if (!Base)
      return;

    State = State->set<ZeroedRegionMap>(Base, true);
    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isCallTo(Call, "Curl_peer_unlink", C))
    return;

  SVal Arg0 = Call.getArgSVal(0);
  const MemRegion *R = getPointeeRegion(Arg0, C);
  if (!R)
    return;

  const MemRegion *Base = R->getBaseRegion();
  ProgramStateRef State = C.getState();

  const bool *ZeroedExact = State->get<ZeroedRegionMap>(R);
  const bool *ZeroedBase = State->get<ZeroedRegionMap>(Base);

  if ((ZeroedExact && *ZeroedExact) || (ZeroedBase && *ZeroedBase)) {
    reportUnlinkAfterZero(Call, C);
  }
}

void SAGenTestChecker::reportUnlinkAfterZero(const CallEvent &Call,
                                             CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unlink after zeroing leaks peer", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unlink after containing structure was zeroed",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
