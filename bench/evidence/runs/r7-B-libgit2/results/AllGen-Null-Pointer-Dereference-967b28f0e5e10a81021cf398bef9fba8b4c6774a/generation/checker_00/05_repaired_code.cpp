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
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked NULL summary passed to git__strdup",
                       "Null Dereference")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "git__strdup", C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *Arg = Call.getArgExpr(0);
  if (!Arg)
    return;

  Arg = Arg->IgnoreParenImpCasts();

  const auto *ME = dyn_cast<MemberExpr>(Arg);
  if (!ME)
    return;

  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD || VD->getName() != "summary")
    return;

  if (!Arg->getType()->isPointerType())
    return;

  ProgramStateRef State = C.getState();
  SVal ArgSVal = State->getSVal(Arg, C.getLocationContext());

  if (SymbolRef Sym = ArgSVal.getAsSymbol()) {
    if (State->isNull(ArgSVal).isConstrainedFalse())
      return; // Definitely non-null.
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked NULL summary passed to git__strdup", N);
  Report->addRange(Arg->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked NULL summary passed to git__strdup",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
