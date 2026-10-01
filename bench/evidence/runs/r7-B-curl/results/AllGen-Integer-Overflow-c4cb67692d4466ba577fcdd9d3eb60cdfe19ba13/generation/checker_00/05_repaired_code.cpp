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
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool containsNarrowInt(const Expr *E) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (QT->isSpecificBuiltinType(BuiltinType::UShort))
        return true;
    }
    return false;
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast<Expr>(Child)) {
      if (containsNarrowInt(CE))
        return true;
    }
  }
  return false;
}

static bool hasNarrowIntInAdd(const Expr *E) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Add) {
      if (containsNarrowInt(BO->getLHS()) || containsNarrowInt(BO->getRHS()))
        return true;
      if (hasNarrowIntInAdd(BO->getLHS()) ||
          hasNarrowIntInAdd(BO->getRHS()))
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

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  Cond = Cond->IgnoreParenImpCasts();

  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GT && Op != BO_LT && Op != BO_GE && Op != BO_LE &&
      Op != BO_EQ && Op != BO_NE)
    return;

  if (!hasNarrowIntInAdd(BO->getLHS()) &&
      !hasNarrowIntInAdd(BO->getRHS()))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Narrow integer type used in size check; may overflow. Use size_t.",
      N);
  Report->addRange(Cond->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects narrow integer types used in size-check additions that may overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
