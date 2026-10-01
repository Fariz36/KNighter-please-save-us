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
#include "llvm/ADT/APSInt.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(ZeroedStructMap, const MemRegion *, bool)

namespace {

static bool callIsNamed(const CallEvent &Call, StringRef Name,
                        CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, Name, C);
}

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Peer leak after struct zeroing",
                       "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Detect memset(dst, 0, ...) and __builtin_memset(dst, 0, ...)
  if (callIsNamed(Call, "memset", C) ||
      callIsNamed(Call, "__builtin_memset", C)) {
    if (Call.getNumArgs() < 2)
      return;

    const Expr *ValExpr = Call.getArgExpr(1);
    llvm::APSInt EvalRes;
    if (!ValExpr || !EvaluateExprToInt(EvalRes, ValExpr, C) ||
        !EvalRes.isZero())
      return;

    SVal Dest = Call.getArgSVal(0);
    const MemRegion *MR = Dest.getAsRegion();
    if (!MR)
      return;

    State = State->set<ZeroedStructMap>(MR, true);
    C.addTransition(State);
    return;
  }

  // Summarize cf_h2_proxy_ctx_clear(ctx): it zeroes the whole ctx object.
  if (callIsNamed(Call, "cf_h2_proxy_ctx_clear", C)) {
    if (Call.getNumArgs() < 1)
      return;

    SVal Arg = Call.getArgSVal(0);
    const MemRegion *MR = Arg.getAsRegion();
    if (!MR)
      return;

    State = State->set<ZeroedStructMap>(MR, true);
    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Detect Curl_peer_unlink(&ctx->dest) after the containing struct was zeroed.
  if (!callIsNamed(Call, "Curl_peer_unlink", C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  SVal Arg = Call.getArgSVal(0);
  const MemRegion *MR = Arg.getAsRegion();
  if (!MR)
    return;

  const MemRegion *Base = MR->getBaseRegion();
  if (!Base)
    Base = MR;

  ProgramStateRef State = C.getState();
  const bool *ZeroedMR = State->get<ZeroedStructMap>(MR);
  const bool *ZeroedBase = State->get<ZeroedStructMap>(Base);

  if ((ZeroedMR && *ZeroedMR) || (ZeroedBase && *ZeroedBase)) {
    reportBug(Call, C);
  }
}

void SAGenTestChecker::reportBug(const CallEvent &Call,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Curl_peer_unlink after containing struct was zeroed; possible peer leak.",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects Curl_peer_unlink after the containing struct was zeroed",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
