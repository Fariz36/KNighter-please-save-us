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
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(OutParamNullMap, const ParmVarDecl *, bool)

namespace {

static bool isOutParam(const ParmVarDecl *PVD) {
  if (!PVD)
    return false;

  QualType QT = PVD->getType().getCanonicalType();
  if (!QT->isPointerType())
    return false;

  QualType Pointee = QT->getPointeeType();
  return Pointee->isPointerType();
}

class SAGenTestChecker
    : public Checker<check::Bind, check::PreStmt<ReturnStmt>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Success with NULL output parameter",
                       "Null Pointer")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S,
                 CheckerContext &C) const;

  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || BO->getOpcode() != BO_Assign)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const UnaryOperator *UO = dyn_cast<UnaryOperator>(LHS);
  if (!UO || UO->getOpcode() != UO_Deref)
    return;

  const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub);
  if (!DRE)
    return;

  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!isOutParam(PVD))
    return;

  ProgramStateRef State = C.getState();
  bool IsNull = Val.isZeroConstant();
  if (!IsNull) {
    if (SymbolRef Sym = Val.getAsSymbol()) {
      auto NullVal = State->getConstraintManager().isNull(State, Sym);
      IsNull = NullVal.isConstrained() && NullVal.getValue();
    }
  }

  State = State->set<OutParamNullMap>(PVD, IsNull);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  SVal RetVal = State->getSVal(RetE, C.getLocationContext());
  bool IsNull = RetVal.isZeroConstant();
  if (!IsNull) {
    if (SymbolRef Sym = RetVal.getAsSymbol()) {
      auto NullVal = State->getConstraintManager().isNull(State, Sym);
      IsNull = NullVal.isConstrained() && NullVal.getValue();
    }
  }
  if (!IsNull)
    return;

  const FunctionDecl *FD =
      dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD)
    return;

  for (const ParmVarDecl *PVD : FD->parameters()) {
    if (!isOutParam(PVD))
      continue;

    const bool *IsNull = State->get<OutParamNullMap>(PVD);
    if (IsNull && *IsNull) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto report = std::make_unique<PathSensitiveBugReport>(
          *BT, "NULL out-parameter returned on success path", N);
      report->addRange(RS->getSourceRange());
      C.emitReport(std::move(report));
      return;
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects success paths that return a NULL output parameter",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
