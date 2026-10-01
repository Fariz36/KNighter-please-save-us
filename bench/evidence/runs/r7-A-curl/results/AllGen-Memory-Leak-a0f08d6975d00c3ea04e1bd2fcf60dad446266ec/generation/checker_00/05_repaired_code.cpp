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
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(ZeroedStructMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unlink after memset may leak peer",
                       "Memory Leak")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportLeak(const CallEvent &Call, CheckerContext &C) const;
};

} // namespace

static bool isMemsetCall(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef Name = ID->getName();
    return Name == "memset" || Name == "__builtin_memset";
  }
  return false;
}

static bool isKnownClearCall(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    return ID->getName() == "cf_h2_proxy_ctx_clear";
  }
  return false;
}

static bool isPeerUnlinkCall(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    return ID->getName() == "Curl_peer_unlink";
  }
  return false;
}

static ProgramStateRef markZeroed(ProgramStateRef State, const MemRegion *Region) {
  if (!Region)
    return State;
  const MemRegion *Base = Region->getBaseRegion();
  if (!Base)
    return State;
  return State->set<ZeroedStructMap>(Base, true);
}

static bool isZeroed(ProgramStateRef State, const MemRegion *Region) {
  if (!Region)
    return false;
  const MemRegion *Base = Region->getBaseRegion();
  if (!Base)
    return false;
  const bool *Zeroed = State->get<ZeroedStructMap>(Base);
  return Zeroed && *Zeroed;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isMemsetCall(Call)) {
    if (Call.getNumArgs() < 3)
      return;

    // If the fill value is known and non-zero, this is not a zeroing
    // operation for the purpose of this checker.
    llvm::APSInt FillVal(32);
    if (EvaluateExprToInt(FillVal, Call.getArgExpr(1), C)) {
      if (FillVal != 0)
        return;
    }

    const Expr *DestExpr = Call.getArgExpr(0);
    if (!DestExpr)
      return;

    const MemRegion *MR = getMemRegionFromExpr(DestExpr, C);
    if (!MR)
      return;

    State = markZeroed(State, MR);
    C.addTransition(State);
    return;
  }

  if (isKnownClearCall(Call)) {
    if (Call.getNumArgs() < 1)
      return;

    const Expr *ArgExpr = Call.getArgExpr(0);
    if (!ArgExpr)
      return;

    const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
    if (!MR)
      return;

    State = markZeroed(State, MR);
    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isPeerUnlinkCall(Call))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;

  const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
  if (!MR)
    return;

  if (isZeroed(C.getState(), MR)) {
    reportLeak(Call, C);
  }
}

void SAGenTestChecker::reportLeak(const CallEvent &Call,
                                  CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unlink after memset may leak peer", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects Curl_peer_unlink after struct was zeroed, which may leak peer",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
