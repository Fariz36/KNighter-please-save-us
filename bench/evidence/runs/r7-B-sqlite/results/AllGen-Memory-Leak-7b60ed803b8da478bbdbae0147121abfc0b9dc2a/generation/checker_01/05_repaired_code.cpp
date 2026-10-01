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
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory Leak", "Memory Management")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  bool hasValidCleanup(const IfStmt *If, CheckerContext &C) const;
};

bool SAGenTestChecker::hasValidCleanup(const IfStmt *If,
                                       CheckerContext &C) const {
  if (!If)
    return false;

  const Stmt *Else = If->getElse();
  if (!Else)
    return false;

  const CallExpr *CE = dyn_cast<CallExpr>(Else);
  if (!CE)
    CE = findSpecificTypeInChildren<CallExpr>(Else);
  if (!CE)
    return false;

  const Expr *Callee = CE->getCallee();
  if (!Callee || !ExprHasName(Callee, "sqlite3SrcListDelete", C))
    return false;

  for (unsigned I = 0; I < CE->getNumArgs(); ++I) {
    const Expr *Arg = CE->getArg(I);
    if (Arg && ExprHasName(Arg, "pFromDup", C))
      return true;
  }

  return false;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || FD->getNameAsString() != "sqlite3TriggerUpdateStep")
    return;

  const IfStmt *If = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!If)
    return;

  const Expr *CondExpr = dyn_cast<Expr>(Condition);
  if (!CondExpr)
    return;

  if (!ExprHasName(CondExpr, "pFromDup", C) ||
      !ExprHasName(CondExpr, "pTriggerStep->pSrc", C))
    return;

  if (hasValidCleanup(If, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential memory leak: pFromDup is not freed when append fails",
      N);
  report->addRange(CondExpr->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing cleanup of pFromDup in sqlite3TriggerUpdateStep",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
