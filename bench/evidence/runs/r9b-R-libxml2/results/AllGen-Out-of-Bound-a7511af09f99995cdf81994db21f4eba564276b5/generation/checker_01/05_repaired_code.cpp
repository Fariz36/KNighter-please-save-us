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
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(DupResultSet, SymbolRef)

namespace {
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "NULL pointer dereference", "Null Dereference")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "duplicator") ||
      !knighter::callIsRole(Call, "null_on_failure"))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = RetVal.getAsLocSymbol();
  if (!Sym)
    return;

  State = State->add<DupResultSet>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "length_of"))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    SVal ArgVal = Call.getArgSVal(i);
    SymbolRef Sym = ArgVal.getAsLocSymbol();
    if (!Sym)
      continue;

    if (!State->contains<DupResultSet>(Sym))
      continue;

    ConditionTruthVal IsNull =
        State->getConstraintManager().isNull(State, Sym);
    if (IsNull.isConstrainedFalse())
      continue;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "NULL pointer dereference: unchecked result of duplicator passed to "
        "length_of",
        N);
    report->addRange(Call.getSourceRange());
    C.emitReport(std::move(report));
    break;
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects NULL dereference when result of a duplicator (null_on_failure) "
      "is passed to length_of before being checked",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "duplicator": {"names": ["xmlStrdup"], "description": "returns a newly allocated copy of its input (e.g., strdup-like)"},
  "null_on_failure": {"names": ["xmlStrdup"], "description": "may return NULL to indicate failure, such as allocation failure"},
  "length_of": {"names": ["strlen"], "description": "computes the length of a C string by dereferencing the pointer argument"}
}
*/
