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
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Null Pointer Dereference", "Null Pointer")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Identify the call to git__strdup.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "git__strdup", C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  // Retrieve the first argument's SVal.
  SVal ArgSVal = Call.getArgSVal(0);

  // The argument must be a location (pointer).
  if (!ArgSVal.getAs<Loc>())
    return;

  // Skip arguments that are definitely non-NULL addresses
  // (e.g., string literals, arrays, &var).
  if (ArgSVal.getAs<loc::MemRegionVal>())
    return;

  // Query the constraint manager for nullness.
  ProgramStateRef State = C.getState();
  ConditionTruthVal IsNull = State->isNull(ArgSVal);

  // If it is definitely non-NULL, there is no bug.
  if (IsNull.isConstrainedFalse())
    return;

  // Report a potential NULL pointer passed to git__strdup.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Potential NULL pointer passed to git__strdup", N);
  Report->addRange(OriginExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects passing potentially NULL pointer to git__strdup",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
