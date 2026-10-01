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

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks whether an output parameter (a T** parameter) is currently known to
// hold NULL on the current path.
REGISTER_MAP_WITH_PROGRAMSTATE(OutputParamNullMap, const ParmVarDecl *, bool)

namespace {
class SAGenTestChecker
    : public Checker<check::Bind, check::PreStmt<ReturnStmt>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Output parameter set to NULL on success return",
                       "Null Pointer")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  if (!S)
    return;

  // Find the assignment expression that caused this bind.
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
  if (!BO) {
    BO = findSpecificTypeInParents<BinaryOperator>(S, C);
  }
  if (!BO || BO->getOpcode() != BO_Assign)
    return;

  // The LHS must be a dereference of a parameter, e.g. *hosts.
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const UnaryOperator *UO = dyn_cast<UnaryOperator>(LHS);
  if (!UO || UO->getOpcode() != UO_Deref)
    return;

  const Expr *SubE = UO->getSubExpr()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(SubE);
  if (!DRE)
    return;

  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD)
    return;

  // Only track pointer-to-pointer output parameters (T **).
  QualType QT = PVD->getType();
  if (!QT->isPointerType() || !QT->getPointeeType()->isPointerType())
    return;

  ProgramStateRef State = C.getState();
  bool IsNull = State->isNull(Val).isConstrainedTrue();

  State = State->set<OutputParamNullMap>(PVD, IsNull);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS,
                                    CheckerContext &C) const {
  if (!RS)
    return;

  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = State->getSVal(RetE, C.getLocationContext());

  // We only care about successful returns (usually zero).
  if (!State->isNull(RetVal).isConstrainedTrue())
    return;

  const LocationContext *LC = C.getLocationContext();
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(LC->getDecl());
  if (!FD)
    return;

  for (auto I : State->get<OutputParamNullMap>()) {
    const ParmVarDecl *PVD = I.first;
    bool IsNull = I.second;

    if (!IsNull)
      continue;

    // Avoid cross-function false positives by ensuring the parameter belongs
    // to the function being analyzed.
    if (PVD->getDeclContext() != FD)
      continue;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      continue;

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Output parameter set to NULL on success return", N);
    Report->addRange(RS->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects output parameters set to NULL on successful return",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
