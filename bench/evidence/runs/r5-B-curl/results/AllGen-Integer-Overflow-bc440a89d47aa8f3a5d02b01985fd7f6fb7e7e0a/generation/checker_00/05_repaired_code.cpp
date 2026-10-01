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

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow in Base64 Size Calculation",
                       "Integer Overflow")) {}

  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO,
                                    CheckerContext &C) const {
  if (!BO)
    return;

  // 1. Filter: must be a multiplication (BO_Mul).
  if (BO->getOpcode() != BO_Mul)
    return;

  // 2. Ensure one operand is an integer literal 4 (e.g. `4 * (...)`)
  //    This matches `4 * (1 + ((size - 1) / 3))`.
  bool HasLiteralFour = false;
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  auto IsLiteralFour = [](const Expr *E) -> bool {
    const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E);
    if (!IL)
      return false;
    return IL->getValue() == 4;
  };
  if (IsLiteralFour(LHS) || IsLiteralFour(RHS))
    HasLiteralFour = true;
  if (!HasLiteralFour)
    return;

  // 3. Ensure the enclosing function is `encoder_base64_size`.
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return;
  const Decl *D = LCtx->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return;
  if (FD->getNameAsString() != "encoder_base64_size")
    return;

  // 4. Get the function body and inspect preceding statements for a guard.
  const Stmt *Body = FD->getBody();
  const CompoundStmt *CS = dyn_cast_or_null<CompoundStmt>(Body);
  if (!CS)
    return;

  // Source location of the multiplication expression.
  SourceLocation MulLoc = BO->getExprLoc();

  // Iterate over the body's top-level statements appearing before MulLoc.
  bool GuardFound = false;
  for (const Stmt *S : CS->body()) {
    if (!S)
      continue;

    // Only consider statements entirely before the multiplication.
    SourceLocation StmtLoc = S->getBeginLoc();
    // If the statement's begin location is after MulLoc, stop (we've passed).
    if (StmtLoc.isValid() && MulLoc.isValid() &&
        C.getSourceManager().isBeforeInTranslationUnit(MulLoc, StmtLoc)) {
      break;
    }

    const IfStmt *If = dyn_cast<IfStmt>(S);
    if (!If)
      continue;

    const Expr *Cond = If->getCond();
    if (!Cond)
      continue;

    // 5. Condition must reference both `size` and `BASE64_MAX_INPUT_SIZE`.
    if (!ExprHasName(Cond, "BASE64_MAX_INPUT_SIZE", C))
      continue;
    if (!ExprHasName(Cond, "size", C))
      continue;

    // 6. Then branch must contain a `return` statement (e.g. `return -1;`).
    if (!findSpecificTypeInChildren<ReturnStmt>(If->getThen()))
      continue;

    // Guard found — overflow is prevented.
    GuardFound = true;
    break;
  }

  if (GuardFound)
    return;

  // No guard found — report a potential overflow.
  auto Report = std::make_unique<BasicBugReport>(
      *BT,
      "Potential integer overflow in base64 size calculation; missing "
      "upper-bound check.",
      PathDiagnosticLocation(BO, C.getSourceManager(),
                             C.getLocationContext()));
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing upper-bound check before overflow-prone base64 size "
      "calculation in encoder_base64_size",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
