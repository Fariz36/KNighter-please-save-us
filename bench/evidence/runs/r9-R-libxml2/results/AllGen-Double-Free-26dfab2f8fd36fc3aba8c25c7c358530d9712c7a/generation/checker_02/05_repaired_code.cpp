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
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state set to track memory regions that have been consumed by a
// parser_input constructor (and therefore must not be freed by the caller).
REGISTER_SET_WITH_PROGRAMSTATE(ConsumedBuffers, const MemRegion *)

namespace {
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double Free", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportDoubleFree(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  // Only interested in parser_input constructors.
  if (!knighter::callIsRole(Call, "parser_input"))
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  // Mark every argument region as consumed by the constructor.
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *ArgExpr = Call.getArgExpr(i);
    if (!ArgExpr)
      continue;

    const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
    if (!MR)
      continue;

    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    // Add to the set if not already present.
    if (!State->contains<ConsumedBuffers>(MR)) {
      State = State->add<ConsumedBuffers>(MR);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Only interested in deallocator calls.
  if (!knighter::callIsRole(Call, "deallocator"))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *ArgExpr = Call.getArgExpr(i);
    if (!ArgExpr)
      continue;

    const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
    if (!MR)
      continue;

    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    // If the region was already consumed by a parser_input constructor,
    // calling a deallocator on it is a double free.
    if (State->contains<ConsumedBuffers>(MR)) {
      reportDoubleFree(Call, C);
      return; // one report per call is enough
    }
  }
}

void SAGenTestChecker::reportDoubleFree(const CallEvent &Call,
                                        CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Double free of buffer consumed by parser_input", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}
} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free of a buffer already consumed by a parser_input constructor",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["xmlNewIOInputStream"], "description": "builds a parser input from a supplied buffer and consumes that buffer"},
  "null_on_failure": {"names": ["xmlNewIOInputStream"], "description": "may return NULL on failure after freeing the consumed buffer"},
  "deallocator": {"names": ["xmlFreeParserInputBuffer"], "description": "frees a parser input buffer"}
}
*/
