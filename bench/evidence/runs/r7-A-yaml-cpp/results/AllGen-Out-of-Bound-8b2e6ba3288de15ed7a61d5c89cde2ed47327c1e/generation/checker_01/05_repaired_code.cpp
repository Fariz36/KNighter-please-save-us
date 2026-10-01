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

#include "clang/AST/ExprCXX.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker
    : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unconditional PopIndent",
                       "Indent Stack Underflow")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  bool isPopIndentCall(const CXXMemberCallExpr *CE) const;
  bool conditionContainsGuard(const Expr *Cond, CheckerContext &C) const;
  void inspectStmt(const Stmt *S, bool Guarded, CheckerContext &C) const;
  void reportBug(const CXXMemberCallExpr *CE, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  // Match the buggy condition: it must mention m_simpleKeys and UNVERIFIED.
  if (!ExprHasName(CondE, "m_simpleKeys", C) ||
      !ExprHasName(CondE, "UNVERIFIED", C))
    return;

  // Find the enclosing IfStmt.
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  // Inspect the then-branch for unguarded PopIndent() calls.
  inspectStmt(IS->getThen(), false, C);
}

bool SAGenTestChecker::isPopIndentCall(const CXXMemberCallExpr *CE) const {
  if (!CE)
    return false;
  const CXXMethodDecl *MD = CE->getMethodDecl();
  if (!MD)
    return false;
  return MD->getName() == "PopIndent";
}

bool SAGenTestChecker::conditionContainsGuard(const Expr *Cond,
                                              CheckerContext &C) const {
  if (!Cond)
    return false;
  // The guard must check both m_indents and the simple key's pIndent.
  return ExprHasName(Cond, "m_indents", C) &&
         ExprHasName(Cond, "pIndent", C);
}

void SAGenTestChecker::inspectStmt(const Stmt *S, bool Guarded,
                                   CheckerContext &C) const {
  if (!S)
    return;

  if (const auto *CE = dyn_cast<CXXMemberCallExpr>(S)) {
    if (isPopIndentCall(CE)) {
      if (!Guarded) {
        reportBug(CE, C);
      }
      return;
    }
  }

  if (const auto *IS = dyn_cast<IfStmt>(S)) {
    bool CondGuarded = conditionContainsGuard(IS->getCond(), C);
    // Traverse the condition just in case, but it should not contain PopIndent.
    inspectStmt(IS->getCond(), Guarded, C);
    // The then-branch is guarded if the condition itself is a guard.
    inspectStmt(IS->getThen(), Guarded || CondGuarded, C);
    // The else-branch is not protected by the guard.
    inspectStmt(IS->getElse(), Guarded, C);
    return;
  }

  // Recurse over all children with the current guard state.
  for (const Stmt *Child : S->children()) {
    inspectStmt(Child, Guarded, C);
  }
}

void SAGenTestChecker::reportBug(const CXXMemberCallExpr *CE,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unconditional PopIndent() may cause indent stack underflow", N);
  report->addRange(CE->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unguarded PopIndent() calls that may cause indent stack underflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
