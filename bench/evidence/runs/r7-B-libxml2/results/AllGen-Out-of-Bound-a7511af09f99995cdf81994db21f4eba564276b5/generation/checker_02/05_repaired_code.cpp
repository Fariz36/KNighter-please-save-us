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
#include "clang/Lex/Lexer.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/Basic/SourceManager.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::PreStmt<ArraySubscriptExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read in NXT macro",
                       "Memory safety")) {}

  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE,
                                    CheckerContext &C) const {
  if (!ASE)
    return;

  // Check that this is an access to ctxt->cur.
  const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
  const MemberExpr *ME = dyn_cast<MemberExpr>(Base);
  if (!ME)
    return;

  if (!ME->isArrow())
    return;

  const ValueDecl *Member = ME->getMemberDecl();
  if (!Member || Member->getName() != "cur")
    return;

  // Verify the base object is a DeclRefExpr referencing 'ctxt'.
  const Expr *Obj = ME->getBase()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Obj);
  if (!DRE || !DRE->getDecl() || DRE->getDecl()->getName() != "ctxt")
    return;

  // Check that the expression comes from the NXT macro.
  const SourceManager &SM = C.getSourceManager();
  SourceLocation Loc = ASE->getBeginLoc();
  if (!SM.isMacroBodyExpansion(Loc))
    return;
  if (Lexer::getImmediateMacroName(Loc, SM, C.getLangOpts()) != "NXT")
    return;

  // Check whether the access is already guarded by the fixed bounds check.
  if (const ConditionalOperator *CO =
          findSpecificTypeInParents<ConditionalOperator>(ASE, C)) {
    const Expr *Cond = CO->getCond();
    if (Cond && ExprHasName(Cond, "len", C) &&
        ExprHasName(Cond, "string", C)) {
      return; // Safe: fixed NXT macro.
    }
  }

  // Report the bug.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Out-of-bounds read in NXT macro", N);
  Report->addRange(ASE->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked out-of-bounds reads in the NXT macro",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
