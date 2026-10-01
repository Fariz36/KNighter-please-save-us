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
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMap.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "llvm/Support/raw_ostream.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class NXTMacroVisitor : public RecursiveASTVisitor<NXTMacroVisitor> {
  const SourceManager &SM;
  ASTContext &AC;
  BugReporter &BR;
  BugType &BT;
  ParentMap &PM;

public:
  NXTMacroVisitor(const SourceManager &SM, ASTContext &AC, BugReporter &BR,
                  BugType &BT, ParentMap &PM)
      : SM(SM), AC(AC), BR(BR), BT(BT), PM(PM) {}

  bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
    SourceLocation Loc = ASE->getBeginLoc();
    if (!Loc.isMacroID())
      return true;

    if (Lexer::getImmediateMacroName(Loc, SM, AC.getLangOpts()) != "NXT")
      return true;

    const Stmt *Parent = PM.getParent(ASE);
    if (const auto *CO = dyn_cast_or_null<ConditionalOperator>(Parent)) {
      SourceLocation COL = CO->getBeginLoc();
      if (COL.isMacroID() &&
          Lexer::getImmediateMacroName(COL, SM, AC.getLangOpts()) == "NXT")
        return true;
    }

    auto Report = std::make_unique<BasicBugReport>(
        BT, "Unchecked NXT macro lookahead may read out of bounds",
        PathDiagnosticLocation::createBegin(ASE, SM, nullptr));
    BR.emitReport(std::move(Report));
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked NXT Macro", "Out-of-bounds Read")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  SourceManager &SM = Mgr.getSourceManager();
  ASTContext &AC = Mgr.getASTContext();

  ParentMap PM(Body);
  NXTMacroVisitor Visitor(SM, AC, BR, *BT, PM);
  Visitor.TraverseStmt(Body);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked NXT macro lookahead in libxml2",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
