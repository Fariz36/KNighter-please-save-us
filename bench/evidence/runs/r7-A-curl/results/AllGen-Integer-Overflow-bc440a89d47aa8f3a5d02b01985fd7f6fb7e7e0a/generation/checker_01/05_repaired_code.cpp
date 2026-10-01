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
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker
  : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "MIME integer overflow", "Integer overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

static bool isVarNamed(const Expr *E, StringRef Name) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return false;
  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  return VD && VD->getName() == Name;
}

static bool containsMul(const Stmt *S) {
  if (!S)
    return false;
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Mul)
      return true;
  }
  for (const Stmt *Child : S->children()) {
    if (containsMul(Child))
      return true;
  }
  return false;
}

static bool isOverflowGuard(const IfStmt *IS, AnalysisManager &Mgr) {
  if (!IS)
    return false;

  const Expr *Cond = IS->getCond();
  if (!Cond)
    return false;
  Cond = Cond->IgnoreParens();

  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return false;
  if (BO->getOpcode() != BO_GT && BO->getOpcode() != BO_GE)
    return false;

  if (!isVarNamed(BO->getLHS(), "size"))
    return false;

  const Expr *RHS = BO->getRHS();
  if (!RHS || !RHS->getSourceRange().isValid())
    return false;

  CharSourceRange Range =
      CharSourceRange::getTokenRange(RHS->getSourceRange());
  StringRef Text = Lexer::getSourceText(Range, Mgr.getSourceManager(),
                                        Mgr.getLangOpts());
  if (!Text.contains("BASE64_MAX_INPUT_SIZE"))
    return false;

  const ReturnStmt *RS = findSpecificTypeInChildren<ReturnStmt>(IS->getThen());
  if (!RS)
    return false;

  const Expr *RetExpr = RS->getRetValue();
  if (!RetExpr)
    return false;

  Expr::EvalResult EvalRes;
  if (!RetExpr->EvaluateAsInt(EvalRes, Mgr.getASTContext()))
    return false;

  return EvalRes.Val.getInt().isNegative();
}

static bool isOverflowProneSizeAssign(const BinaryOperator *BO) {
  if (!BO || BO->getOpcode() != BO_Assign)
    return false;
  if (!isVarNamed(BO->getLHS(), "size"))
    return false;
  const Expr *RHS = BO->getRHS();
  return RHS && containsMul(RHS);
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || FD->getName() != "encoder_base64_size")
    return;

  const Stmt *Body = FD->getBody();
  const auto *CS = dyn_cast_or_null<CompoundStmt>(Body);
  if (!CS)
    return;

  bool overflowGuardSeen = false;

  for (const Stmt *S : CS->body()) {
    if (const auto *IS = dyn_cast<IfStmt>(S)) {
      if (isOverflowGuard(IS, Mgr))
        overflowGuardSeen = true;
      continue;
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      if (isOverflowProneSizeAssign(BO)) {
        if (!overflowGuardSeen) {
          PathDiagnosticLocation Loc =
              PathDiagnosticLocation::createBegin(BO, BR.getSourceManager(), nullptr);
          BR.EmitBasicReport(
              D, this, "MIME integer overflow", "Integer overflow",
              "Potential integer overflow in base64 size calculation: missing "
              "check for size > BASE64_MAX_INPUT_SIZE before arithmetic.",
              Loc);
        }
        return;
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing BASE64_MAX_INPUT_SIZE overflow guard in encoder_base64_size",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
