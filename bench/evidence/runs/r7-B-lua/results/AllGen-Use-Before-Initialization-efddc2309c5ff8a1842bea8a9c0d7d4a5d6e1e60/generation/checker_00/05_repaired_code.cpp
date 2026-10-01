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

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class MatchdepthAssignmentVisitor
    : public RecursiveASTVisitor<MatchdepthAssignmentVisitor> {
public:
  bool Found = false;

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (const MemberExpr *ME = dyn_cast<MemberExpr>(LHS)) {
        if (ME->getMemberDecl()->getNameAsString() == "matchdepth") {
          Found = true;
          return false; // Stop traversal once assignment is found.
        }
      }
    }
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing matchdepth reset",
                       "Iterator State Error")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

private:
  bool hasMatchdepthAssignment(const Stmt *Body) const;
  void reportMissingReset(const FunctionDecl *FD, BugReporter &BR) const;
};

} // end anonymous namespace

bool SAGenTestChecker::hasMatchdepthAssignment(const Stmt *Body) const {
  if (!Body)
    return false;

  MatchdepthAssignmentVisitor Visitor;
  Visitor.TraverseStmt(const_cast<Stmt *>(Body));
  return Visitor.Found;
}

void SAGenTestChecker::reportMissingReset(const FunctionDecl *FD,
                                          BugReporter &BR) const {
  PathDiagnosticLocation Loc =
      PathDiagnosticLocation::createBegin(FD, BR.getSourceManager());
  auto Report = std::make_unique<BasicBugReport>(
      *BT,
      "Missing reset of matchdepth in reprepstate; iterator state may be "
      "inconsistent after error.",
      Loc);
  Report->addRange(FD->getSourceRange());
  BR.emitReport(std::move(Report));
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  if (FD->getNameAsString() != "reprepstate")
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  if (!hasMatchdepthAssignment(Body)) {
    reportMissingReset(FD, BR);
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing reset of matchdepth in reprepstate",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
