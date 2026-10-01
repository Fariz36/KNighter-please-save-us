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
#include "clang/AST/StmtCXX.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class EmptyIndentGuardVisitor : public RecursiveASTVisitor<EmptyIndentGuardVisitor> {
public:
  bool Found = false;

  bool VisitCXXMemberCallExpr(CXXMemberCallExpr *CE) {
    if (Found)
      return false;

    const CXXMethodDecl *MD = CE->getMethodDecl();
    if (!MD)
      return true;

    if (MD->getNameAsString() != "empty")
      return true;

    const Expr *Obj = CE->getImplicitObjectArgument();
    if (!Obj)
      return true;

    Obj = Obj->IgnoreImpCasts();
    if (const auto *ME = dyn_cast<MemberExpr>(Obj)) {
      if (const ValueDecl *VD = ME->getMemberDecl()) {
        if (VD->getNameAsString() == "m_indents") {
          Found = true;
          return false;
        }
      }
    }
    return true;
  }
};

class SAGenTestChecker : public Checker<check::PreCall, check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Indent Stack Underflow", "Logic")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const Expr *CE = Call.getOriginExpr();
  if (!CE)
    return;

  const auto *MCE = dyn_cast<CXXMemberCallExpr>(CE);
  if (!MCE)
    return;

  const CXXMethodDecl *MD = MCE->getMethodDecl();
  if (!MD)
    return;

  if (MD->getNameAsString() != "PopIndent")
    return;

  const CXXRecordDecl *Parent = MD->getParent();
  if (!Parent || Parent->getNameAsString() != "Scanner")
    return;

  const IfStmt *If = findSpecificTypeInParents<IfStmt>(MCE, C);
  if (!If)
    return;

  const Expr *Cond = If->getCond();
  if (!Cond)
    return;

  // Check if the condition is about an unverified simple key.
  if (!ExprHasName(Cond, "m_simpleKeys", C) || !ExprHasName(Cond, "UNVERIFIED", C))
    return;

  // Check for required guards.
  bool HasEmptyGuard = ExprHasName(Cond, "m_indents.empty()", C);
  bool HasMatchGuard = ExprHasName(Cond, "m_indents.top() == m_simpleKeys.top().pIndent", C);

  if (HasEmptyGuard && HasMatchGuard)
    return; // properly guarded

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "PopIndent() called without checking indent stack; possible underflow.",
      N);
  Report->addRange(MCE->getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &,
                                        BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  const auto *MD = dyn_cast<CXXMethodDecl>(FD);
  if (!MD)
    return;

  if (MD->getNameAsString() != "PopIndent")
    return;

  const CXXRecordDecl *Parent = MD->getParent();
  if (!Parent || Parent->getNameAsString() != "Scanner")
    return;

  Stmt *Body = MD->getBody();
  if (!Body)
    return;

  EmptyIndentGuardVisitor V;
  V.TraverseStmt(Body);

  if (V.Found)
    return;

  auto Report = std::make_unique<BasicBugReport>(
      *BT,
      "PopIndent() does not check for empty indent stack.",
      PathDiagnosticLocation(Body, BR.getSourceManager(), nullptr));
  BR.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing indent stack guards in Scanner::PopIndent calls",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
