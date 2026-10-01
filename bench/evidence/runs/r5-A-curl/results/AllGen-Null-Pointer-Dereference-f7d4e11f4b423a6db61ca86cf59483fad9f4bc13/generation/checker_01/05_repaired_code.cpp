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

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static const MemberExpr *getDataMember(const Expr *E) {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();

  const auto *ME = dyn_cast<MemberExpr>(E);
  if (!ME)
    return nullptr;

  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD || VD->getName() != "data")
    return nullptr;

  if (!ME->getType()->isPointerType())
    return nullptr;

  return ME;
}

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Null Pointer Dereference",
                       "Dereference of nullable 'data' member")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportNullDataDeref(const Expr *Arg, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  if (!ExprHasName(Origin, "memcpy", C) &&
      !ExprHasName(Origin, "memmove", C))
    return;

  if (Call.getNumArgs() < 3)
    return;

  // If the size is a constant zero, there is no meaningful access.
  if (const Expr *SizeE = Call.getArgExpr(2)) {
    llvm::APSInt SizeVal;
    if (EvaluateExprToInt(SizeVal, SizeE, C) && SizeVal.isZero())
      return;
  }

  ProgramStateRef State = C.getState();

  for (unsigned Idx = 0; Idx < 2; ++Idx) {
    const Expr *Arg = Call.getArgExpr(Idx);
    if (!Arg || !getDataMember(Arg))
      continue;

    SVal Val = State->getSVal(Arg, C.getLocationContext());
    if (!Val.getAs<Loc>())
      continue;

    if (Val.isZeroConstant()) {
      reportNullDataDeref(Arg, C);
      continue;
    }

    SymbolRef Sym = Val.getAsSymbol();
    if (!Sym)
      continue;

    ConditionTruthVal IsNull = State->isNull(Val);
    if (!IsNull.isConstrainedFalse())
      reportNullDataDeref(Arg, C);
  }
}

void SAGenTestChecker::reportNullDataDeref(const Expr *Arg,
                                           CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "NULL pointer dereference: 'data' member may be NULL", N);
  Report->addRange(Arg->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects possible NULL pointer dereference of 'data' member in memcpy/memmove",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
