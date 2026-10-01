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
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool isNarrowIntegerType(QualType QT, ASTContext &Ctx) {
  if (!QT->isIntegerType())
    return false;
  return Ctx.getTypeSize(QT) < 32;
}

static bool containsNarrowVar(const Stmt *S, ASTContext &Ctx) {
  if (!S)
    return false;

  if (const Expr *E = dyn_cast<Expr>(S)) {
    E = E->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (isNarrowIntegerType(VD->getType(), Ctx))
          return true;
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (containsNarrowVar(Child, Ctx))
      return true;
  }
  return false;
}

static bool hasNarrowAdd(const Stmt *S, ASTContext &Ctx) {
  if (!S)
    return false;

  if (const Expr *E = dyn_cast<Expr>(S)) {
    E = E->IgnoreParenImpCasts();
    if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_Add) {
        if (containsNarrowVar(BO->getLHS(), Ctx) ||
            containsNarrowVar(BO->getRHS(), Ctx))
          return true;
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (hasNarrowAdd(Child, Ctx))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Narrow integer type in size check may cause integer overflow",
                       "Integer Overflow")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenImpCasts();

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return;

  switch (BO->getOpcode()) {
  case BO_GT:
  case BO_GE:
  case BO_LT:
  case BO_LE:
    break;
  default:
    return;
  }

  if (!hasNarrowAdd(CondE, C.getASTContext()))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Narrow integer type in size check may cause integer overflow",
      N);
  Report->addRange(Condition->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in size checks caused by narrow integer types",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
