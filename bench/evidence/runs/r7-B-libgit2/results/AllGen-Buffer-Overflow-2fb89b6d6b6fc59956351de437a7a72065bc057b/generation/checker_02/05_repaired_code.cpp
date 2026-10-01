#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Set of memory regions that are length-delimited and not guaranteed to be
// NUL-terminated within their bounds.
REGISTER_SET_WITH_PROGRAMSTATE(LengthDelimitedBuffers, const MemRegion *)

namespace {
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read", "Memory Safety")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportUnboundedStringCall(const CallEvent &Call,
                                 CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "memchr", C))
    return;

  ProgramStateRef State = C.getState();
  SVal ArgSVal = Call.getArgSVal(0);
  const MemRegion *BuffRegion = ArgSVal.getAsRegion();
  if (!BuffRegion)
    return;

  BuffRegion = BuffRegion->getBaseRegion();
  if (!BuffRegion)
    return;

  State = State->add<LengthDelimitedBuffers>(BuffRegion);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  if (!ExprHasName(OriginExpr, "strstr", C) &&
      !ExprHasName(OriginExpr, "strchr", C))
    return;

  ProgramStateRef State = C.getState();
  SVal ArgSVal = Call.getArgSVal(0);
  const MemRegion *ArgRegion = ArgSVal.getAsRegion();
  if (!ArgRegion)
    return;

  // Walk up the super region chain to see if this pointer points into a
  // length-delimited buffer.
  for (const MemRegion *R = ArgRegion; R; ) {
    if (State->contains<LengthDelimitedBuffers>(R)) {
      reportUnboundedStringCall(Call, C);
      return;
    }

    if (const auto *SubR = dyn_cast<SubRegion>(R))
      R = SubR->getSuperRegion();
    else
      R = nullptr;
  }
}

void SAGenTestChecker::reportUnboundedStringCall(const CallEvent &Call,
                                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unbounded string function on length-delimited buffer may read out of "
      "bounds.",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded string functions on length-delimited buffers",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
