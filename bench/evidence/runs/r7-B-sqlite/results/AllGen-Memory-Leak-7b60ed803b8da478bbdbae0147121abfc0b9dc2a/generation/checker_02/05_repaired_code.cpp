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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/ADT/StringRef.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Potential SrcList leak",
                       "Memory Leak")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  bool isCallTo(const CallExpr *CE, StringRef Name, CheckerContext &C) const;
  const VarDecl *getPendingVar(const CallExpr *CE, unsigned ArgIdx) const;
  bool elseCleansVar(const Stmt *Else, const VarDecl *Var,
                     CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isCallTo(const CallExpr *CE, StringRef Name,
                                CheckerContext &C) const {
  if (!CE)
    return false;

  // Use ExprHasName as required for accurate callee-name checking.
  if (!ExprHasName(CE, Name, C))
    return false;

  // Also confirm through the direct callee to avoid matching the name only
  // because it appears in an argument expression.
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return false;

  return FD->getName() == Name;
}

const VarDecl *SAGenTestChecker::getPendingVar(const CallExpr *CE,
                                               unsigned ArgIdx) const {
  if (!CE || CE->getNumArgs() <= ArgIdx)
    return nullptr;

  const Expr *Arg = CE->getArg(ArgIdx);
  if (!Arg)
    return nullptr;

  Arg = Arg->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Arg);
  if (!DRE)
    return nullptr;

  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD || !VD->isLocalVarDecl())
    return nullptr;

  return VD;
}

bool SAGenTestChecker::elseCleansVar(const Stmt *Else, const VarDecl *Var,
                                     CheckerContext &C) const {
  if (!Else)
    return false;

  const CallExpr *DeleteCE = findSpecificTypeInChildren<CallExpr>(Else);
  if (!isCallTo(DeleteCE, "sqlite3SrcListDelete", C))
    return false;

  for (unsigned I = 0; I < DeleteCE->getNumArgs(); ++I) {
    const Expr *Arg = DeleteCE->getArg(I);
    if (!Arg)
      continue;

    Arg = Arg->IgnoreParenImpCasts();
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Arg);
    if (!DRE)
      continue;

    const VarDecl *D = dyn_cast<VarDecl>(DRE->getDecl());
    if (D == Var)
      return true;

    if (D && D->getName() == Var->getName())
      return true;
  }

  return false;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Stmt *Then = IS->getThen();
  if (!Then)
    return;

  const CallExpr *AppendCE = findSpecificTypeInChildren<CallExpr>(Then);
  if (!isCallTo(AppendCE, "sqlite3SrcListAppendList", C))
    return;

  // sqlite3SrcListAppendList(pParse, existingList, pendingList)
  // The pending SrcList is the third argument (index 2).
  const VarDecl *PendingVar = getPendingVar(AppendCE, 2);
  if (!PendingVar)
    return;

  // The same variable must be tested in the if condition.
  const Expr *Cond = IS->getCond();
  if (!Cond || !ExprHasName(Cond, PendingVar->getName(), C))
    return;

  // If the false branch already frees the pending SrcList, this is not a leak.
  const Stmt *Else = IS->getElse();
  if (Else && elseCleansVar(Else, PendingVar, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential SrcList leak: ownership not transferred and not freed on failure path.",
      N);
  Report->addRange(IS->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potential SrcList leak when ownership transfer fails",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
