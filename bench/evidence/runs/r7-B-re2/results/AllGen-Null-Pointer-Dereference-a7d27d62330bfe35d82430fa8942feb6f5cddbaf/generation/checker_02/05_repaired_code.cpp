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
#include "clang/AST/DeclCXX.h"
#include "clang/AST/ExprCXX.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Returns true if the expression is a negated call to a method named "empty".
// This matches patterns like:  !ss->empty()
static bool isNegatedEmptyCall(const Expr *E) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  const UnaryOperator *UO = dyn_cast<UnaryOperator>(E);
  if (!UO || UO->getOpcode() != UO_LNot)
    return false;

  const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();

  if (const CXXMemberCallExpr *MCE = dyn_cast<CXXMemberCallExpr>(Sub)) {
    if (const CXXMethodDecl *MD = MCE->getMethodDecl()) {
      return MD->getName() == "empty";
    }
  }

  if (const CallExpr *CE = dyn_cast<CallExpr>(Sub)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      return FD->getName() == "empty";
    }
  }

  return false;
}

// Returns true if Target is a descendant of Root (or is Root itself).
static bool containsStmt(const Stmt *Root, const Stmt *Target) {
  if (!Root || !Target)
    return false;
  if (Root == Target)
    return true;

  for (const Stmt *Child : Root->children()) {
    if (containsStmt(Child, Target))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Conditional NULL return", "Logic Error")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  // Only consider pointer-returning functions.
  if (!FD->getReturnType()->isPointerType())
    return;

  // Restrict to Prefilter::OrStrings to avoid false positives.
  const CXXMethodDecl *MD = dyn_cast<CXXMethodDecl>(FD);
  if (!MD)
    return;
  const CXXRecordDecl *RD = MD->getParent();
  if (!RD || RD->getName() != "Prefilter" || MD->getName() != "OrStrings")
    return;

  // Pass 1: find a ReturnStmt that returns a local pointer variable.
  struct ReturnVisitor : public RecursiveASTVisitor<ReturnVisitor> {
    SmallVector<const ReturnStmt *, 4> Returns;
    bool VisitReturnStmt(const ReturnStmt *RS) {
      Returns.push_back(RS);
      return true;
    }
  } RV;
  RV.TraverseStmt(FD->getBody());

  const VarDecl *TargetVar = nullptr;
  const ReturnStmt *TargetReturn = nullptr;
  for (const ReturnStmt *RS : RV.Returns) {
    const Expr *RetE = RS->getRetValue();
    if (!RetE)
      continue;
    RetE = RetE->IgnoreParenImpCasts();

    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(RetE);
    if (!DRE)
      continue;
    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD || !VD->isLocalVarDecl())
      continue;
    if (!VD->getType()->isPointerType())
      continue;

    TargetVar = VD;
    TargetReturn = RS;
    break;
  }
  if (!TargetVar || !TargetReturn)
    return;

  // Check that the variable is initialized to NULL.
  const Expr *Init = TargetVar->getInit();
  if (!Init)
    return;
  if (!Init->isNullPointerConstant(Mgr.getASTContext(),
                                   Expr::NPC_ValueDependentIsNull))
    return;

  // Pass 2: find the matching if-statement and all non-NULL assignments to V.
  struct PatternVisitor : public RecursiveASTVisitor<PatternVisitor> {
    const VarDecl *V;
    const IfStmt *TargetIf = nullptr;
    SmallVector<const BinaryOperator *, 4> NonNullAssigns;

    explicit PatternVisitor(const VarDecl *V) : V(V) {}

    bool VisitIfStmt(const IfStmt *IS) {
      if (!TargetIf && isNegatedEmptyCall(IS->getCond())) {
        TargetIf = IS;
      }
      return true;
    }

    bool VisitBinaryOperator(const BinaryOperator *BO) {
      if (BO->getOpcode() != BO_Assign)
        return true;

      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS);
      if (!DRE || DRE->getDecl() != V)
        return true;

      const Expr *RHS = BO->getRHS();
      if (RHS->isNullPointerConstant(V->getASTContext(),
                                     Expr::NPC_ValueDependentIsNull))
        return true;

      NonNullAssigns.push_back(BO);
      return true;
    }
  } PV(TargetVar);
  PV.TraverseStmt(FD->getBody());

  if (!PV.TargetIf)
    return;

  const IfStmt *TargetIf = PV.TargetIf;
  const Stmt *Then = TargetIf->getThen();
  if (!Then)
    return;

  // The return must not be inside the if-statement.
  if (containsStmt(TargetIf, TargetReturn))
    return;

  const SourceManager &SM = Mgr.getSourceManager();
  if (!SM.isBeforeInTranslationUnit(TargetIf->getBeginLoc(),
                                   TargetReturn->getBeginLoc()))
    return;

  bool FoundInsideThen = false;
  for (const BinaryOperator *BO : PV.NonNullAssigns) {
    if (containsStmt(Then, BO)) {
      FoundInsideThen = true;
    } else {
      // Non-NULL assignment outside the then-branch. If it occurs before
      // the return, the empty path might get a non-NULL value.
      if (SM.isBeforeInTranslationUnit(BO->getBeginLoc(),
                                       TargetReturn->getBeginLoc()))
        return;
    }
  }

  if (!FoundInsideThen)
    return;

  // Report the bug.
  PathDiagnosticLocation Loc =
      PathDiagnosticLocation::createBegin(TargetIf, SM, nullptr);
  auto R = std::make_unique<BasicBugReport>(
      *BT, "Return value may be NULL when set is empty", Loc);
  R->setDeclWithIssue(FD);
  R->addRange(TargetIf->getSourceRange());
  BR.emitReport(std::move(R));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects Prefilter::OrStrings returning NULL when set is empty",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
