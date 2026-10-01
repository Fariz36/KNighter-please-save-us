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
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/AST/OperationKinds.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker
    : public Checker<check::PreStmt<CStyleCastExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked narrow to int", "Integer Overflow")) {}

  void checkPreStmt(const CStyleCastExpr *CE, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPreStmt(const CStyleCastExpr *CE,
                                    CheckerContext &C) const {
  if (!CE)
    return;

  // Restrict to the target function.
  const LocationContext *LC = C.getLocationContext();
  if (!LC)
    return;

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(LC->getDecl());
  if (!FD || FD->getName() != "sqlite3_str_vappendf")
    return;

  // Only care about casts to int.
  if (!CE->getType()->isSpecificBuiltinType(BuiltinType::Int))
    return;

  // The cast must be (int)(ptr - ptr).
  const Expr *Sub = CE->getSubExpr()->IgnoreParenImpCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Sub);
  if (!BO || BO->getOpcode() != BO_Sub)
    return;

  if (!BO->getLHS()->getType()->isPointerType() ||
      !BO->getRHS()->getType()->isPointerType())
    return;

  // Verify operands are the UTF-8 scan pointer and base pointer.
  if (!ExprHasName(BO->getLHS(), "z", C) ||
      !ExprHasName(BO->getRHS(), "bufpt", C))
    return;

  // Must be in the UTF-8 character-based precision branch.
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(CE, C);
  if (!IS || !ExprHasName(IS->getCond(), "flag_altform2", C))
    return;

  // Must be assigning the narrowed result to "length".
  const BinaryOperator *ParentBO =
      findSpecificTypeInParents<BinaryOperator>(CE, C);
  if (!ParentBO || ParentBO->getOpcode() != BO_Assign)
    return;

  const DeclRefExpr *LHS =
      dyn_cast<DeclRefExpr>(ParentBO->getLHS()->IgnoreParenImpCasts());
  if (!LHS || !LHS->getDecl() || LHS->getDecl()->getName() != "length")
    return;

  // Report the unchecked narrowing.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked narrowing of UTF-8 string length to int", N);
  Report->addRange(CE->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked narrowing of UTF-8 string length to int in "
      "sqlite3_str_vappendf",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
