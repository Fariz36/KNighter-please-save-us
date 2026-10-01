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

#include "clang/AST/DeclCXX.h"
#include "clang/AST/ExprCXX.h"
#include "clang/Basic/OperatorKinds.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/ASTContext.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker
    : public Checker<check::PreCall,
                     check::PreStmt<ArraySubscriptExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Buffer underflow",
                       "Out-of-bounds access")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;

private:
  bool isCountMinusOne(const Expr *IndexExpr, const Expr *&CountExpr,
                       CheckerContext &C) const;
  bool isCountPositive(const Expr *CountExpr, CheckerContext &C) const;
  void checkIndexExpr(const Expr *IndexExpr, CheckerContext &C) const;
  void reportBug(const Expr *IndexExpr, CheckerContext &C) const;
};

bool SAGenTestChecker::isCountMinusOne(const Expr *IndexExpr,
                                       const Expr *&CountExpr,
                                       CheckerContext &C) const {
  IndexExpr = IndexExpr->IgnoreParenCasts();
  const auto *BO = dyn_cast<BinaryOperator>(IndexExpr);
  if (!BO || BO->getOpcode() != BO_Sub)
    return false;

  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, RHS, C) || EvalRes.getZExtValue() != 1)
    return false;

  CountExpr = BO->getLHS()->IgnoreParenCasts();
  if (!CountExpr->getType()->isIntegerType())
    return false;

  return true;
}

bool SAGenTestChecker::isCountPositive(const Expr *CountExpr,
                                       CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SVal CountVal = State->getSVal(CountExpr, C.getLocationContext());

  if (auto CI = CountVal.getAs<nonloc::ConcreteInt>()) {
    const llvm::APSInt &Val = CI->getValue();
    if (Val.isSigned())
      return Val.getSExtValue() > 0;
    return Val.getZExtValue() > 0;
  }

  SymbolRef Sym = CountVal.getAsSymbol();
  if (Sym) {
    const llvm::APSInt *MinVal =
        State->getConstraintManager().getSymMinVal(State, Sym);
    if (MinVal) {
      if (MinVal->isSigned())
        return MinVal->getSExtValue() > 0;
      return MinVal->getZExtValue() > 0;
    }
  }

  return false;
}

void SAGenTestChecker::checkIndexExpr(const Expr *IndexExpr,
                                      CheckerContext &C) const {
  const Expr *CountExpr = nullptr;
  if (!isCountMinusOne(IndexExpr, CountExpr, C))
    return;

  if (isCountPositive(CountExpr, C))
    return;

  reportBug(IndexExpr, C);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Decl *D = Call.getDecl();
  const auto *MD = dyn_cast_or_null<CXXMethodDecl>(D);
  if (!MD || MD->getOverloadedOperator() != OO_Subscript)
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *IndexExpr = Call.getArgExpr(1);
  if (!IndexExpr)
    return;

  checkIndexExpr(IndexExpr, C);
}

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE,
                                    CheckerContext &C) const {
  const Expr *IndexExpr = ASE->getIdx();
  checkIndexExpr(IndexExpr, C);
}

void SAGenTestChecker::reportBug(const Expr *IndexExpr,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Buffer underflow: accessing container[count - 1] without checking "
      "count > 0",
      N);
  Report->addRange(IndexExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects buffer underflow when accessing container[count - 1] without "
      "checking count > 0",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
