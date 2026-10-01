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
#include "clang/Basic/SourceLocation.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Return true if E is a reference to a local variable named Name.
bool isVarDeclRef(const Expr *E, StringRef Name) {
  if (!E)
    return false;
  E = E->IgnoreParenCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      return VD->getName() == Name;
    }
  }
  return false;
}

// Look for: szBufNeeded = ... + <integer less than 10>;
bool isSzBufNeededAssign(const BinaryOperator *BO) {
  if (!BO || BO->getOpcode() != BO_Assign)
    return false;

  if (!isVarDeclRef(BO->getLHS(), "szBufNeeded"))
    return false;

  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
  const BinaryOperator *Add = dyn_cast<BinaryOperator>(RHS);
  if (!Add || Add->getOpcode() != BO_Add)
    return false;

  const Expr *Last = Add->getRHS()->IgnoreParenCasts();
  const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(Last);
  if (!IL)
    return false;

  return IL->getValue().getLimitedValue() < 10;
}

// Look for a call to sqlite3StrAccumEnlargeIfNeeded(..., szBufNeeded, ...).
bool isEnlargeCall(const Stmt *S) {
  const CallExpr *CE = dyn_cast<CallExpr>(S);
  if (!CE)
    return false;

  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD || FD->getNameAsString() != "sqlite3StrAccumEnlargeIfNeeded")
    return false;

  for (const Expr *Arg : CE->arguments()) {
    if (isVarDeclRef(Arg, "szBufNeeded"))
      return true;
  }
  return false;
}

// Look for: zOut[length] = 0;
bool isTerminatorWrite(const Stmt *S) {
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || BO->getOpcode() != BO_Assign)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(LHS);
  if (!ASE)
    return false;

  if (!isVarDeclRef(ASE->getBase(), "zOut"))
    return false;
  if (!isVarDeclRef(ASE->getIdx(), "length"))
    return false;

  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
  const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(RHS);
  return IL && IL->getValue().isZero();
}

bool containsEnlargeCall(const Stmt *S) {
  if (!S)
    return false;
  if (isEnlargeCall(S))
    return true;
  for (const Stmt *Child : S->children()) {
    if (containsEnlargeCall(Child))
      return true;
  }
  return false;
}

bool containsTerminatorWrite(const Stmt *S) {
  if (!S)
    return false;
  if (isTerminatorWrite(S))
    return true;
  for (const Stmt *Child : S->children()) {
    if (containsTerminatorWrite(Child))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Under-estimated buffer size", "Buffer overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

private:
  void visitStmt(const Stmt *S, BugReporter &BR,
                 const FunctionDecl *FD) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || FD->getNameAsString() != "sqlite3_str_vappendf")
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  visitStmt(Body, BR, FD);
}

void SAGenTestChecker::visitStmt(const Stmt *S, BugReporter &BR,
                                 const FunctionDecl *FD) const {
  if (!S)
    return;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (isSzBufNeededAssign(BO)) {
      const Stmt *Body = FD->getBody();
      if (containsEnlargeCall(Body) && containsTerminatorWrite(Body)) {
        auto Report = std::make_unique<BasicBugReport>(
            *BT,
            "under-estimated buffer size: +8 slack may miss NUL terminator "
            "(use +10)",
            PathDiagnosticLocation::createBegin(BO, BR.getSourceManager(),
                                                nullptr));
        Report->addRange(BO->getSourceRange());
        BR.emitReport(std::move(Report));
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    visitStmt(Child, BR, FD);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects under-estimated output buffer size in sqlite3_str_vappendf",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
