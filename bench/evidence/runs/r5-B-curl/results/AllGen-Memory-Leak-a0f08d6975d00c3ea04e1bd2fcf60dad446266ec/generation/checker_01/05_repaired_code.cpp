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
#include "llvm/ADT/StringRef.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(ZeroedRegions, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unlink after memset", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee)
    return;

  StringRef Name = Callee->getName();
  if (Name != "memset" && Name != "__builtin_memset")
    return;

  if (Call.getNumArgs() < 3)
    return;

  llvm::APSInt FillVal;
  if (!EvaluateExprToInt(FillVal, Call.getArgExpr(1), C))
    return;
  if (!FillVal.isZero())
    return;

  const MemRegion *DestR = getMemRegionFromExpr(Call.getArgExpr(0), C);
  if (!DestR)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<ZeroedRegions>(DestR);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee)
    return;

  if (Callee->getName() != "Curl_peer_unlink")
    return;

  if (Call.getNumArgs() < 1)
    return;

  const MemRegion *ArgR = getMemRegionFromExpr(Call.getArgExpr(0), C);
  if (!ArgR)
    return;

  ProgramStateRef State = C.getState();
  bool Zeroed = State->contains<ZeroedRegions>(ArgR);
  if (!Zeroed) {
    const MemRegion *BaseR = ArgR->getBaseRegion();
    if (BaseR)
      Zeroed = State->contains<ZeroedRegions>(BaseR);
  }

  if (!Zeroed)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unlinking list node after memset zeroed its structure", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unlinking embedded list nodes after memset zeroed the containing structure",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
