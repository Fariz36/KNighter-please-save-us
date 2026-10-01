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
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "NULL pointer argument to string duplication",
                       "Null Pointer")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

static bool isStringDupFunction(const CallEvent &Call, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  return ExprHasName(OriginExpr, "git__strdup", C) ||
         ExprHasName(OriginExpr, "strdup", C) ||
         ExprHasName(OriginExpr, "git__strndup", C) ||
         ExprHasName(OriginExpr, "strndup", C);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isStringDupFunction(Call, C))
    return;

  if (Call.getNumArgs() == 0)
    return;

  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;

  // Focus on pointer-typed expressions that are direct field or variable
  // references, matching the "nullable string field" pattern.
  QualType ArgTy = ArgExpr->getType();
  if (!ArgTy->isPointerType())
    return;

  const Expr *InnerExpr = ArgExpr->IgnoreParenImpCasts();
  if (!isa<MemberExpr>(InnerExpr) && !isa<DeclRefExpr>(InnerExpr))
    return;

  ProgramStateRef State = C.getState();
  SVal ArgVal = State->getSVal(ArgExpr, C.getLocationContext());

  auto ArgLoc = ArgVal.getAs<Loc>();
  if (!ArgLoc)
    return;

  // Check whether the argument can be NULL on this path.
  ProgramStateRef NullState = State->assume(*ArgLoc, false);
  if (!NullState)
    return; // NULL is infeasible; safe.

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Possible NULL passed to string duplication function", N);
  Report->addRange(ArgExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects possibly NULL string fields passed to string duplication "
      "functions without a NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
