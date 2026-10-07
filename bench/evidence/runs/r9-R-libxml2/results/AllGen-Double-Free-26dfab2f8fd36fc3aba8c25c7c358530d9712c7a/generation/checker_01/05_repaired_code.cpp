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
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(OwnedOnFailureMap, SymbolRef, SymbolRef)

namespace {

static SymbolRef getSymbolFromSVal(SVal V) {
  if (SymbolRef Sym = V.getAsLocSymbol(true))
    return Sym;
  return V.getAsSymbol(true);
}

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this, "Double free", "Memory error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportDoubleFree(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "null_on_failure"))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef RetSym = getSymbolFromSVal(RetVal);
  if (!RetSym)
    return;

  bool Changed = false;
  for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
    SVal ArgVal = Call.getArgSVal(I);
    SymbolRef ArgSym = getSymbolFromSVal(ArgVal);
    if (!ArgSym)
      continue;

    State = State->set<OwnedOnFailureMap>(ArgSym, RetSym);
    Changed = true;
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "deallocator"))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
    SVal ArgVal = Call.getArgSVal(I);
    SymbolRef ArgSym = getSymbolFromSVal(ArgVal);
    if (!ArgSym)
      continue;

    const SymbolRef *RetSymPtr = State->get<OwnedOnFailureMap>(ArgSym);
    if (!RetSymPtr)
      continue;

    SymbolRef RetSym = *RetSymPtr;
    if (State->isNull(nonloc::SymbolVal(RetSym)).isConstrainedTrue()) {
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
      "Double free: resource may already have been freed by failing initializer",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free when a failing initializer already freed the resource",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "null_on_failure": {"names": ["xmlNewIOInputStream"], "description": "initializer/factory that may return NULL; on failure it takes ownership of and deallocates a resource passed as an argument"},
  "deallocator": {"names": ["xmlFreeParserInputBuffer"], "description": "frees a resource/object; the pointer must not be used or freed again afterwards"}
}
*/
