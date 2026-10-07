#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Map from a buffer region to the return symbol of the parser input constructor
// that may free the buffer on failure.
REGISTER_MAP_WITH_PROGRAMSTATE(BufferToReturnSymMap, const MemRegion *, SymbolRef)

namespace {
/* The checker callbacks are to be decided. */
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
   mutable std::unique_ptr<BugType> BT;

   public:
      SAGenTestChecker() : BT(new BugType(this, "Double Free", "Memory Management")) {}

      void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
      void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

   private:
      void reportDoubleFree(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  // Only track parser input constructors that may return NULL on failure.
  if (!knighter::callIsRole(Call, "parser_input") ||
      !knighter::callIsRole(Call, "null_on_failure"))
    return;

  SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
  if (!RetSym)
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    const Expr *Arg = Call.getArgExpr(I);
    if (!Arg)
      continue;

    const MemRegion *MR = getMemRegionFromExpr(Arg, C);
    if (!MR)
      continue;

    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    State = State->set<BufferToReturnSymMap>(MR, RetSym);
    Changed = true;
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Only inspect deallocator calls.
  if (!knighter::callIsRole(Call, "deallocator"))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    const Expr *Arg = Call.getArgExpr(I);
    if (!Arg)
      continue;

    const MemRegion *MR = getMemRegionFromExpr(Arg, C);
    if (!MR)
      continue;

    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    const SymbolRef *RetSymPtr = State->get<BufferToReturnSymMap>(MR);
    if (!RetSymPtr)
      continue;

    SymbolRef RetSym = *RetSymPtr;
    SVal RetSymVal = C.getSValBuilder().makeSymbolVal(RetSym);
    ConditionTruthVal IsNull = State->isNull(RetSymVal);
    if (IsNull.isConstrainedTrue()) {
      reportDoubleFree(Call, C);
      return;
    }
  }
}

void SAGenTestChecker::reportDoubleFree(const CallEvent &Call,
                                        CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Double free: buffer already freed by parser input constructor on failure.",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free when a parser input constructor frees its buffer on "
      "failure and the caller also frees it.",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["xmlNewIOInputStream"], "description": "constructs a parser input from a buffer; may return NULL on failure"},
  "null_on_failure": {"names": ["xmlNewIOInputStream"], "description": "function that may return NULL on failure"},
  "deallocator": {"names": ["xmlFreeParserInputBuffer"], "description": "frees a parser input buffer; the buffer must not be used afterwards"}
}
*/
