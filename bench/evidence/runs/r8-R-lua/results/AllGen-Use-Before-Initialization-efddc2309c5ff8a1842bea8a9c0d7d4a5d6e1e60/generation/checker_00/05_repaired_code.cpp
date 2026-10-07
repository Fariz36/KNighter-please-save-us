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

#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class GuardVisitor : public RecursiveASTVisitor<GuardVisitor> {
public:
  bool CheckAssignment = false;
  bool CheckGuardCheck = false;
  bool CheckGuardRestore = false;
  bool CheckResetterCall = false;

  bool FoundAssignment = false;
  bool FoundGuardCheck = false;
  bool FoundGuardRestore = false;
  bool FoundResetterCall = false;

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (CheckAssignment && BO->getOpcode() == BO_Assign) {
      Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (isGuardCounterMember(LHS)) {
        FoundAssignment = true;
      }
    }
    if (CheckGuardRestore && BO->getOpcode() == BO_AddAssign) {
      Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (isGuardCounterMember(LHS)) {
        FoundGuardRestore = true;
      }
    }
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (CheckGuardRestore) {
      if (UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc) {
        Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
        if (isGuardCounterMember(Sub)) {
          FoundGuardRestore = true;
        }
      }
    }
    return true;
  }

  bool VisitIfStmt(IfStmt *IS) {
    if (CheckGuardCheck && isGuardCheckWithAbort(IS)) {
      FoundGuardCheck = true;
    }
    return true;
  }

  bool VisitCallExpr(CallExpr *CE) {
    if (CheckResetterCall && callIsRole(CE, "per_match_state_resetter")) {
      FoundResetterCall = true;
    }
    return true;
  }

private:
  static bool isGuardCounterMember(const Expr *E) {
    E = E->IgnoreParenImpCasts();
    const MemberExpr *ME = dyn_cast<MemberExpr>(E);
    if (!ME) return false;
    const ValueDecl *Member = ME->getMemberDecl();
    if (!Member) return false;
    if (!knighter::declIsRole(Member, "transient_guard_counter")) return false;
    if (const RecordDecl *RD = dyn_cast<RecordDecl>(Member->getDeclContext())) {
      if (!knighter::declIsRole(RD, "state_object")) return false;
    }
    return true;
  }

  static bool callIsRole(const CallExpr *CE, const char *Role) {
    if (!CE) return false;
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      return knighter::isRole(Role, FD->getNameAsString());
    }
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(
            CE->getCallee()->IgnoreParenImpCasts())) {
      if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
        return knighter::isRole(Role, FD->getNameAsString());
      }
    }
    return false;
  }

  static const Expr *stripLikelyAndNot(const Expr *E) {
    while (E) {
      E = E->IgnoreParenImpCasts();
      if (const CallExpr *CE = dyn_cast<CallExpr>(E)) {
        if (const FunctionDecl *FD = CE->getDirectCallee()) {
          if (FD->getName() == "__builtin_expect" && CE->getNumArgs() >= 1) {
            E = CE->getArg(0);
            continue;
          }
        }
      }
      if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
        if (UO->getOpcode() == UO_LNot) {
          E = UO->getSubExpr();
          continue;
        }
      }
      break;
    }
    return E;
  }

  static bool isZeroLiteral(const Expr *E) {
    E = E->IgnoreParenImpCasts();
    if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
      return IL->getValue() == 0;
    }
    return false;
  }

  static bool isGuardCheckWithAbort(IfStmt *IS) {
    const Expr *Cond = IS->getCond();
    if (!Cond) return false;
    Cond = stripLikelyAndNot(Cond);
    const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond);
    if (!BO || BO->getOpcode() != BO_EQ) return false;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

    bool LHSZero = isZeroLiteral(LHS);
    bool RHSZero = isZeroLiteral(RHS);
    if (!LHSZero && !RHSZero) return false;

    const Expr *DecExpr = LHSZero ? RHS : LHS;
    const UnaryOperator *UO = dyn_cast<UnaryOperator>(DecExpr);
    if (!UO) return false;
    if (UO->getOpcode() != UO_PostDec && UO->getOpcode() != UO_PreDec) return false;
    const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
    if (!isGuardCounterMember(Sub)) return false;

    const Stmt *Then = IS->getThen();
    if (!Then) return false;
    return stmtContainsCallToRole(Then, "non_local_error_abort");
  }

  static bool stmtContainsCallToRole(const Stmt *S, const char *Role) {
    if (!S) return false;
    if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
      if (callIsRole(CE, Role)) return true;
    }
    for (const Stmt *Child : S->children()) {
      if (stmtContainsCallToRole(Child, Role)) return true;
    }
    return false;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody, check::EndAnalysis> {
  mutable std::unique_ptr<BugType> BT;

  mutable bool InitializerInitializesGuard = false;
  mutable bool GuardCheckWithAbort = false;
  mutable bool GuardRestoreSeen = false;
  mutable bool IteratorReusesResetter = false;
  mutable bool ResetterResetsGuard = false;
  mutable SourceLocation ResetterLoc;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Inconsistent reusable state", "Logic Error")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD) return;
  const Stmt *Body = FD->getBody();
  if (!Body) return;

  std::string FnName = FD->getNameAsString();
  bool IsInitializer = knighter::isRole("state_initializer", FnName);
  bool IsResetter = knighter::isRole("per_match_state_resetter", FnName);
  bool IsIterator = knighter::isRole("reusing_iterator", FnName);

  if (IsResetter) {
    ResetterLoc = FD->getLocation();
  }

  GuardVisitor V;
  V.CheckGuardCheck = true;
  V.CheckGuardRestore = true;
  V.CheckAssignment = IsInitializer || IsResetter;
  V.CheckResetterCall = IsIterator;
  V.TraverseStmt(const_cast<Stmt *>(Body));

  if (V.FoundAssignment) {
    if (IsInitializer) InitializerInitializesGuard = true;
    if (IsResetter) ResetterResetsGuard = true;
  }
  if (V.FoundGuardCheck) GuardCheckWithAbort = true;
  if (V.FoundGuardRestore) GuardRestoreSeen = true;
  if (V.FoundResetterCall) IteratorReusesResetter = true;
}

void SAGenTestChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                                        ExprEngine &Eng) const {
  if (!InitializerInitializesGuard || !GuardCheckWithAbort || !GuardRestoreSeen ||
      !IteratorReusesResetter || !ResetterLoc.isValid() || ResetterResetsGuard)
    return;

  PathDiagnosticLocation L(ResetterLoc, BR.getSourceManager());
  auto Report = std::make_unique<BasicBugReport>(
      *BT, "Per-match reset does not reinitialize transient guard counter", L);
  Report->addNote(
      "A non-local error can leave the counter exhausted; the reused state "
      "fails to detect the next overflow.",
      L);
  BR.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects reusable state objects whose transient guard counter is not "
      "reset per match, allowing non-local errors to bypass overflow checks",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "state_object": {"names": ["MatchState", "GMatchState"], "description": "struct that holds reusable matching state"},
  "state_initializer": {"names": ["prepstate"], "description": "one-time initializer for the reusable state object"},
  "per_match_state_resetter": {"names": ["reprepstate"], "description": "routine that resets per-match fields on a reused state object"},
  "transient_guard_counter": {"names": ["matchdepth"], "description": "field that tracks recursion/stack-depth and is decremented before recursive calls and incremented on normal exit"},
  "guard_check": {"names": [], "description": "condition that checks the transient guard counter before recursion"},
  "guard_restore": {"names": [], "description": "operation that restores the transient guard counter on normal exit"},
  "non_local_error_abort": {"names": ["luaL_error", "lua_error"], "description": "function/macro that aborts via non-local error, skipping cleanup"},
  "reusing_iterator": {"names": ["gmatch_aux", "gmatch"], "description": "iterator/closure that reuses the state object across multiple matches"}
}
*/
