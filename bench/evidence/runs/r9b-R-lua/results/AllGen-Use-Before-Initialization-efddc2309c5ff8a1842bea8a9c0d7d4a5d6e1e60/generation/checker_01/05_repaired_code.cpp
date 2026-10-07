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
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class MissingResetVisitor
    : public RecursiveASTVisitor<MissingResetVisitor> {
  ASTContext &ASTCtx;
  BugReporter &BR;
  BugType &BT;
  llvm::SmallPtrSet<const FieldDecl *, 8> AssignedFields;
  llvm::SmallPtrSet<const FieldDecl *, 8> ReportedFields;

public:
  MissingResetVisitor(ASTContext &C, BugReporter &R, BugType &B)
      : ASTCtx(C), BR(R), BT(B) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Assign)
      return true;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const auto *ME = dyn_cast<MemberExpr>(LHS);
    if (!ME)
      return true;

    const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!FD)
      return true;

    AssignedFields.insert(FD);
    return true;
  }

  bool VisitCallExpr(CallExpr *CE) {
    if (!knighter::callExprIsRole(CE, "aborting_assert", ASTCtx))
      return true;

    if (CE->getNumArgs() == 0)
      return true;

    const Expr *Cond = CE->getArg(0)->IgnoreParenImpCasts();
    const auto *BO = dyn_cast<BinaryOperator>(Cond);
    if (!BO)
      return true;

    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op != BO_EQ && Op != BO_NE)
      return true;

    auto CheckOperand = [&](const Expr *E) {
      E = E->IgnoreParenImpCasts();
      const auto *ME = dyn_cast<MemberExpr>(E);
      if (!ME)
        return;

      const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
      if (!FD)
        return;

      if (AssignedFields.count(FD) || ReportedFields.count(FD))
        return;

      ReportedFields.insert(FD);

      auto Report = std::make_unique<BasicBugReport>(
          BT, "Missing reset of safety counter",
          PathDiagnosticLocation(CE->getBeginLoc(), ASTCtx.getSourceManager()));
      Report->addRange(CE->getSourceRange());
      Report->addNote("The asserted counter is not reset in this init "
                      "function; an aborted operation may leave it stale.",
                      PathDiagnosticLocation(CE->getBeginLoc(),
                                             ASTCtx.getSourceManager()));
      BR.emitReport(std::move(Report));
    };

    CheckOperand(BO->getLHS());
    CheckOperand(BO->getRHS());
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing Reset of Safety Counter",
                       "Logic Error")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const auto *FD = dyn_cast<FunctionDecl>(D);
    if (!FD || !FD->hasBody())
      return;

    if (!knighter::declIsRole(FD, "init"))
      return;

    Stmt *Body = FD->getBody();
    if (!Body)
      return;

    MissingResetVisitor Visitor(Mgr.getASTContext(), BR, *BT);
    Visitor.TraverseStmt(Body);
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing reset of a safety counter in per-operation init functions",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "init": {"names": ["prepstate", "reprepstate"], "description": "function that initializes or reinitializes a persistent state object used by later operations"},
  "aborting_assert": {"names": ["lua_assert"], "description": "macro/function that aborts when its condition is false; its condition should be an invariant before the operation"},
  "error_setter": {"names": ["luaL_error"], "description": "printf-like function that reports a runtime error and aborts the current operation"}
}
*/
