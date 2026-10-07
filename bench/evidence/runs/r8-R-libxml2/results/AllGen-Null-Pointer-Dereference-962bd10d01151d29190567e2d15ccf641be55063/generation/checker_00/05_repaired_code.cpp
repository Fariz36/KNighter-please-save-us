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
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Dereference of NULL pointer parameter before null check",
                       "Null Pointer")) {}

  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  const Expr *E = dyn_cast<Expr>(S);
  if (!E)
    return;

  // If this is a store through an assignment, examine the left-hand side.
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Assign) {
      E = BO->getLHS();
    }
  }

  E = E->IgnoreParenImpCasts();

  const UnaryOperator *UO = dyn_cast<UnaryOperator>(E);
  if (!UO || UO->getOpcode() != UO_Deref)
    return;

  const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub);
  if (!DRE)
    return;

  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD)
    return;

  if (!knighter::declIsRole(PVD, "inout_capacity_pointer"))
    return;

  SVal PtrVal = C.getState()->getSVal(DRE, C.getLocationContext());
  auto PtrValDef = PtrVal.getAs<DefinedOrUnknownSVal>();
  if (!PtrValDef)
    return;

  // If assuming the pointer is NULL is feasible, the pointer may be NULL.
  if (C.getState()->assume(*PtrValDef, false)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Dereference of NULL pointer parameter before null check", N);
    Report->addRange(UO->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of NULL pointer parameter before null check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "inout_capacity_pointer": {
    "names": ["capacity"],
    "description": "Pointer parameter that is read and written via dereference; must be validated non-NULL before any dereference."
  }
}
*/
