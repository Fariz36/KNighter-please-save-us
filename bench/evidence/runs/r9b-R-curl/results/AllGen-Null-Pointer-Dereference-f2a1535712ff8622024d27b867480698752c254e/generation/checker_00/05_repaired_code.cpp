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

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "knighter/roles.h"

#include <memory>
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::Bind, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL check before writing through pointer argument",
                       "Null Pointer Dereference")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportMissingNullCheck(CheckerContext &C, const Stmt *S) const;
};

void SAGenTestChecker::reportMissingNullCheck(CheckerContext &C,
                                              const Stmt *S) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing NULL check before writing through pointer argument", N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  const auto *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const auto *UO = dyn_cast<UnaryOperator>(LHS);
  if (!UO || UO->getOpcode() != UO_Deref)
    return;

  const Expr *SubExpr = UO->getSubExpr()->IgnoreParenCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(SubExpr);
  if (!DRE)
    return;

  const ValueDecl *VD = DRE->getDecl();
  if (!VD)
    return;

  const auto *PVD = dyn_cast<ParmVarDecl>(VD);
  if (!PVD)
    return;

  if (!PVD->getType()->isPointerType())
    return;

  SVal PtrSVal = C.getState()->getSVal(SubExpr, C.getLocationContext());
  if (auto PtrDV = PtrSVal.getAs<DefinedOrUnknownSVal>()) {
    if (C.getState()->assume(*PtrDV, false)) {
      reportMissingNullCheck(C, S);
    }
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "write_through_callee"))
    return;

  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  for (unsigned i : DerefParams) {
    if (i >= Call.getNumArgs())
      continue;

    const Expr *Arg = Call.getArgExpr(i);
    if (!Arg)
      continue;

    const Expr *ArgIgnored = Arg->IgnoreParenCasts();
    const auto *DRE = dyn_cast<DeclRefExpr>(ArgIgnored);
    if (!DRE)
      continue;

    const ValueDecl *VD = DRE->getDecl();
    if (!VD)
      continue;

    const auto *PVD = dyn_cast<ParmVarDecl>(VD);
    if (!PVD)
      continue;

    if (!PVD->getType()->isPointerType())
      continue;

    SVal PtrSVal = C.getState()->getSVal(ArgIgnored, C.getLocationContext());
    if (auto PtrDV = PtrSVal.getAs<DefinedOrUnknownSVal>()) {
      if (C.getState()->assume(*PtrDV, false)) {
        reportMissingNullCheck(C, Call.getOriginExpr());
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL check before writing through a pointer argument",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "write_through_callee": {"names": ["Curl_easy_recv"], "description": "function that writes an output value through one of its pointer parameters; the pointer argument must not be NULL unless the callee checks it"}
}
*/
