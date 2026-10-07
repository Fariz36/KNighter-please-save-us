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
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(ConsumedResourceMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double Free", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportDoubleFree(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "parser_input"))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    const Expr *ArgE = Call.getArgExpr(I);
    if (!ArgE || !ArgE->getType()->isPointerType())
      continue;

    const MemRegion *R = Call.getArgSVal(I).getAsRegion();
    if (!R)
      continue;

    R = R->getBaseRegion();
    if (!R)
      continue;

    State = State->set<ConsumedResourceMap>(R, true);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "deallocator"))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    const Expr *ArgE = Call.getArgExpr(I);
    if (!ArgE || !ArgE->getType()->isPointerType())
      continue;

    const MemRegion *R = Call.getArgSVal(I).getAsRegion();
    if (!R)
      continue;

    R = R->getBaseRegion();
    if (!R)
      continue;

    const bool *Consumed = State->get<ConsumedResourceMap>(R);
    if (Consumed && *Consumed) {
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

  auto BR = std::make_unique<PathSensitiveBugReport>(
      *BT, "Double free of resource consumed by parser_input", N);
  BR->addRange(Call.getSourceRange());
  C.emitReport(std::move(BR));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free of resources consumed by parser_input-like constructors",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["xmlNewIOInputStream"], "description": "constructor that takes ownership of a resource argument; on failure it frees/consumes that argument and returns NULL, so the caller must not deallocate it afterwards."},
  "deallocator": {"names": ["xmlFreeParserInputBuffer"], "description": "frees the resource passed to a parser_input constructor; must not be called after ownership transfer."},
  "null_on_failure": {"names": ["xmlNewIOInputStream"], "description": "function that may return NULL on failure."}
}
*/
