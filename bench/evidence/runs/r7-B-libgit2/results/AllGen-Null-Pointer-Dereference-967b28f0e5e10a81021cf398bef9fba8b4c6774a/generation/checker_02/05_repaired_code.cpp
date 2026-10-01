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
#include "clang/AST/Decl.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked nullable string field passed to git__strdup",
                       "Null Dereference")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  bool isKnownNonNull(ProgramStateRef State, SVal ArgVal) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isKnownNonNull(ProgramStateRef State, SVal ArgVal) const {
  if (ArgVal.isUnknown())
    return false;

  if (auto L = ArgVal.getAs<Loc>()) {
    // Try assuming the pointer is null. If that assumption is infeasible,
    // the pointer is known to be non-null.
    ProgramStateRef NullState = State->assume(*L, false);
    return !NullState;
  }

  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee || Callee->getName() != "git__strdup")
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;

  ArgExpr = ArgExpr->IgnoreParenImpCasts();
  const auto *ME = dyn_cast<MemberExpr>(ArgExpr);
  if (!ME)
    return;

  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD || VD->getName() != "summary")
    return;

  SVal ArgVal = Call.getArgSVal(0);
  if (ArgVal.isUnknown())
    return;

  ProgramStateRef State = C.getState();
  if (isKnownNonNull(State, ArgVal))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked nullable string field passed to git__strdup", N);
  Report->addRange(ArgExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects git__strdup calls on nullable string fields without a NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
