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

// Recursive AST visitor that walks a function body looking for an `IfStmt`
// whose condition references `TK_ILLEGAL` (typically a comparison of `t`
// against `TK_ILLEGAL`) with a `ReturnStmt` in the then-branch.  This mirrors
// the shape of the guard that was added in the target patch:
//
//     if( t==TK_ILLEGAL ){ *pRes = 1; return SQLITE_OK; }
//
// If such a statement exists in the function body, we consider the function
// "guarded".  Otherwise, we treat any call into the dequoting path as unsafe.
class IllegalTokenGuardVisitor
    : public RecursiveASTVisitor<IllegalTokenGuardVisitor> {
public:
  bool FoundGuard = false;

  bool VisitIfStmt(IfStmt *IS) {
    if (FoundGuard || !IS)
      return true;

    const Stmt *Cond = IS->getCond();
    if (!Cond)
      return true;

    if (!stmtContainsIllegalToken(Cond))
      return true;

    // Require a return in the then branch.
    const Stmt *Then = IS->getThen();
    if (!Then)
      return true;

    if (containsReturn(Then)) {
      FoundGuard = true;
      return false;
    }
    return true;
  }

private:
  // Look for the identifier `TK_ILLEGAL` anywhere inside the given statement.
  static bool stmtContainsIllegalToken(const Stmt *S) {
    if (!S)
      return false;

    // Fast path: syntactic token scan.
    if (const Expr *E = dyn_cast<Expr>(S)) {
      switch (E->getStmtClass()) {
      case Stmt::DeclRefExprClass: {
        const auto *DRE = cast<DeclRefExpr>(E);
        if (const ValueDecl *VD = DRE->getDecl()) {
          if (VD->getName() == "TK_ILLEGAL")
            return true;
        }
        return false;
      }
      case Stmt::BinaryOperatorClass:
      case Stmt::CompoundAssignOperatorClass: {
        const auto *BO = cast<BinaryOperator>(E);
        return stmtContainsIllegalToken(BO->getLHS()) ||
               stmtContainsIllegalToken(BO->getRHS());
      }
      case Stmt::UnaryOperatorClass:
      case Stmt::ParenExprClass: {
        for (const Stmt *Child : E->children())
          if (stmtContainsIllegalToken(Child))
            return true;
        return false;
      }
      default:
        for (const Stmt *Child : E->children())
          if (stmtContainsIllegalToken(Child))
            return true;
        return false;
      }
    }

    for (const Stmt *Child : S->children())
      if (stmtContainsIllegalToken(Child))
        return true;
    return false;
  }

  // Check whether the subtree rooted at S contains a `return` statement.
  static bool containsReturn(const Stmt *S) {
    if (!S)
      return false;
    if (isa<ReturnStmt>(S))
      return true;
    for (const Stmt *Child : S->children())
      if (containsReturn(Child))
        return true;
    return false;
  }
};

class SAGenTestChecker
    : public Checker<check::PreCall, check::ASTDecl<FunctionDecl>> {
  mutable std::unique_ptr<BugType> BT;

  // Names of functions that forward into sqlite3Dequote() on possibly
  // unvalidated input.  We track these as the sources of the bug.
  bool isTargetCallee(StringRef Name) const {
    return Name == "quotedCompare" || Name == "sqlite3Dequote";
  }

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unguarded call into sqlite3Dequote",
                       "sqlite3 API misuse")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr,
                    BugReporter &BR) const;
};

// Return true if the function definition body contains the
// `if( t==TK_ILLEGAL ){ ... return ...; }` guard.
static bool hasIllegalTokenGuard(const FunctionDecl *FD) {
  if (!FD)
    return false;
  const Stmt *Body = FD->getBody();
  if (!Body)
    // No body available (e.g. forward decl).  Conservatively report as
    // guarded so that we don't emit spurious warnings about declarations.
    return true;

  IllegalTokenGuardVisitor V;
  V.TraverseStmt(const_cast<Stmt *>(Body));
  return V.FoundGuard;
}

// Issue the warning at a given statement / node.
static void reportBug(const Stmt *S, CheckerContext &C,
                      std::unique_ptr<BugType> &BT) {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unvalidated token passed to sqlite3Dequote", N);
  if (S)
    Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

// ---------------------------------------------------------------------------
// checkASTDecl: fired for every top-level FunctionDecl.  We use this to
// inspect the definition of the dequoting wrapper and confirm that the
// TK_ILLEGAL guard is present.  If the guard is missing and the function is
// known to forward into the dequoting path, we report the bug at the
// definition site.
// ---------------------------------------------------------------------------
void SAGenTestChecker::checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr,
                                    BugReporter &BR) const {
  if (!D)
    return;

  StringRef Name = D->getName();
  if (!isTargetCallee(Name))
    return;

  // Only inspect definitions that carry a body.
  if (!D->doesThisDeclarationHaveABody())
    return;

  if (hasIllegalTokenGuard(D))
    return;

  // Emit a BasicBugReport anchored at the function definition.  We cannot
  // call C.emitReport here since we're not inside an ExplodedNode context;
  // use the BugReporter directly.
  SourceManager &SM = Mgr.getSourceManager();
  PathDiagnosticLocation L =
      PathDiagnosticLocation::createBegin(D, SM);
  auto Report = std::make_unique<BasicBugReport>(
      *BT, "Unvalidated token passed to sqlite3Dequote", L);
  Report->addRange(D->getSourceRange());
  BR.emitReport(std::move(Report));
}

// ---------------------------------------------------------------------------
// checkPreCall: local checks at the call site.  If the wrapper function is
// invoked directly and we can see the callee's body, verify that the guard
// is present.  This catches cases where the checker is compiled against a
// single TU instead of the whole program.
// ---------------------------------------------------------------------------
void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee)
    return;

  StringRef Name = Callee->getName();
  if (!isTargetCallee(Name))
    return;

  // If the callee has a definition visible in this TU, verify the guard.
  const Decl *CalleeDecl = Call.getDecl();
  if (const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(CalleeDecl)) {
    if (FD->doesThisDeclarationHaveABody() && hasIllegalTokenGuard(FD))
      return;
  } else {
    // We don't have a definition; be conservative and skip to avoid false
    // positives on cross-TU calls we can't inspect.
    return;
  }

  // The guard is missing: the caller is invoking an unguarded dequoting
  // helper.  Report it.
  const Expr *OriginExpr = Call.getOriginExpr();
  reportBug(OriginExpr ? cast<Stmt>(OriginExpr) : nullptr, C, BT);
}

// ===----------------------------------------------------------------------===//
// Checker Registration
// ===----------------------------------------------------------------------===//

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unguarded calls into sqlite3Dequote that can trip on "
      "TK_ILLEGAL tokens from getConstraintToken()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
