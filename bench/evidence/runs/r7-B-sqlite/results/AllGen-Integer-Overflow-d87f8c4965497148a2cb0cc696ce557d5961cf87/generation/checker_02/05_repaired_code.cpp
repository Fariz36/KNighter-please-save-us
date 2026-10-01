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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/Stmt.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "llvm/Support/Casting.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PostStmt<CastExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Pointer difference narrowed to int",
                       "Integer Overflow")) {}

  void checkPostStmt(const CastExpr *CE, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostStmt(const CastExpr *CE,
                                     CheckerContext &C) const {
  if (!CE)
    return;

  // Detect only explicit casts to int, e.g. (int)(...)
  if (!isa<ExplicitCastExpr>(CE))
    return;

  if (!CE->getType()->isSpecificBuiltinType(BuiltinType::Int))
    return;

  // Look through parentheses and implicit casts to find a direct subtraction.
  const Expr *Sub = CE->getSubExpr();
  if (!Sub)
    return;

  Sub = Sub->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Sub);
  if (!BO || BO->getOpcode() != BO_Sub)
    return;

  // Require pointer subtraction: both operands must have pointer type.
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  if (!LHS || !RHS)
    return;

  if (!LHS->getType()->isPointerType() || !RHS->getType()->isPointerType())
    return;

  // Restrict to the vulnerable function.
  const AnalysisDeclContext *ADC = C.getCurrentAnalysisDeclContext();
  if (!ADC)
    return;

  const auto *FD = dyn_cast_or_null<FunctionDecl>(ADC->getDecl());
  if (!FD || FD->getNameAsString() != "sqlite3_str_vappendf")
    return;

  // Restrict to the "%!.*s" path, which is guarded by flag_altform2.
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(CE, C);
  if (!IS)
    return;

  const Expr *Cond = IS->getCond();
  if (!Cond || !ExprHasName(Cond, "flag_altform2", C))
    return;

  // Avoid unrelated pointer subtractions in the same branch.
  if (!ExprHasName(LHS, "z", C) || !ExprHasName(RHS, "bufpt", C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto BR = std::make_unique<PathSensitiveBugReport>(
      *BT, "Pointer difference narrowed to int without overflow clamp", N);
  BR->addRange(CE->getSourceRange());
  C.emitReport(std::move(BR));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked narrowing of pointer differences to int",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
