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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(ClearedPtrs, SymbolRef, bool)

namespace {
class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Resource cleanup after struct clear",
                       "Resource Leak")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  bool isFunctionNamed(const CallEvent &Call, StringRef Name,
                       CheckerContext &C) const;
  void reportCleanupAfterClear(const CallEvent &Call, CheckerContext &C) const;
};

bool SAGenTestChecker::isFunctionNamed(const CallEvent &Call, StringRef Name,
                                       CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  return ExprHasName(OriginExpr, Name, C);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Track memset() that clears a struct.
  if (isFunctionNamed(Call, "memset", C) ||
      isFunctionNamed(Call, "__builtin_memset", C)) {
    if (Call.getNumArgs() < 1)
      return;

    SVal Dest = Call.getArgSVal(0);
    if (SymbolRef Sym = Dest.getAsLocSymbol()) {
      State = State->set<ClearedPtrs>(Sym, true);
      C.addTransition(State);
    }
    return;
  }

  // Detect cleanup of a field after its containing struct was cleared.
  if (isFunctionNamed(Call, "Curl_peer_unlink", C)) {
    if (Call.getNumArgs() < 1)
      return;

    const Expr *Arg = Call.getArgExpr(0);
    if (!Arg)
      return;

    const MemRegion *MR = getMemRegionFromExpr(Arg, C);
    if (!MR)
      return;

    // Only consider cleanup on a field, e.g. &ctx->dest.
    if (MR->getBaseRegion() == MR)
      return;

    const MemRegion *Base = MR->getBaseRegion();
    if (!Base)
      return;

    const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(Base);
    if (!SR)
      return;

    SymbolRef Sym = SR->getSymbol();
    if (!Sym)
      return;

    const bool *Cleared = State->get<ClearedPtrs>(Sym);
    if (Cleared && *Cleared) {
      reportCleanupAfterClear(Call, C);
    }
  }
}

void SAGenTestChecker::reportCleanupAfterClear(const CallEvent &Call,
                                               CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Resource cleanup after struct clear may leak", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects resource cleanup after the containing struct was cleared",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
