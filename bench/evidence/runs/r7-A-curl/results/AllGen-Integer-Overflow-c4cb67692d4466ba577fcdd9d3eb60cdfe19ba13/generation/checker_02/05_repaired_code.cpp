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

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool isNarrowIntegerType(QualType QT, ASTContext &Ctx) {
  if (QT.isNull() || !QT->isIntegerType())
    return false;
  return Ctx.getTypeSize(QT) <= 16;
}

static bool containsSizeof(const Expr *E) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  if (const auto *UETT = dyn_cast<UnaryExprOrTypeTraitExpr>(E)) {
    if (UETT->getKind() == UETT_SizeOf)
      return true;
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast<Expr>(Child)) {
      if (containsSizeof(CE))
        return true;
    }
  }
  return false;
}

static bool containsNarrowIntVar(const Expr *E, ASTContext &Ctx) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (isNarrowIntegerType(VD->getType(), Ctx))
        return true;
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast<Expr>(Child)) {
      if (containsNarrowIntVar(CE, Ctx))
        return true;
    }
  }
  return false;
}

static bool hasNarrowIntAndSizeofInAdd(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Add) {
      if (containsSizeof(BO) && containsNarrowIntVar(BO, C.getASTContext()))
        return true;
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast<Expr>(Child)) {
      if (hasNarrowIntAndSizeofInAdd(CE, C))
        return true;
    }
  }
  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Narrow integer overflow in size check",
                       "Integer Overflow")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                           CheckerContext &C) const {
  const auto *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GT && Op != BO_GE && Op != BO_LT && Op != BO_LE)
    return;

  const Expr *CheckedExpr = nullptr;
  const Expr *BoundExpr = nullptr;

  if (Op == BO_GT || Op == BO_GE) {
    CheckedExpr = BO->getLHS();
    BoundExpr = BO->getRHS();
  } else {
    CheckedExpr = BO->getRHS();
    BoundExpr = BO->getLHS();
  }

  if (!CheckedExpr || !BoundExpr)
    return;

  // Optional refinement: avoid reporting when the bound side is itself narrow.
  if (isNarrowIntegerType(BoundExpr->getType(), C.getASTContext()))
    return;

  if (!hasNarrowIntAndSizeofInAdd(CheckedExpr, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Narrow integer type used in size check; may overflow", N);
  Report->addRange(Condition->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects narrow integer types used in size checks that may overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
