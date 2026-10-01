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
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Division by zero", "Arithmetic")) {}

  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;

private:
  bool isMaxAmplExpr(const Expr *E, CheckerContext &C) const;
  bool containsMaxAmplZeroCheck(const Expr *E, CheckerContext &C) const;
  void reportDivByZero(const BinaryOperator *BO, CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isMaxAmplExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const MemberExpr *ME = dyn_cast<MemberExpr>(E)) {
    if (const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl()))
      return FD->getName() == "maxAmpl";
  }

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const ValueDecl *VD = DRE->getDecl())
      return VD->getName() == "maxAmpl";
  }

  return false;
}

bool SAGenTestChecker::containsMaxAmplZeroCheck(const Expr *E,
                                                CheckerContext &C) const {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    // A guard in either part of a logical AND is sufficient for our
    // conservative syntactic check.
    if (BO->getOpcode() == BO_LAnd) {
      return containsMaxAmplZeroCheck(BO->getLHS(), C) ||
             containsMaxAmplZeroCheck(BO->getRHS(), C);
    }

    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_GT || Op == BO_NE || Op == BO_LT) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      llvm::APSInt LHSInt, RHSInt;
      bool LHSZero = EvaluateExprToInt(LHSInt, LHS, C) && LHSInt == 0;
      bool RHSZero = EvaluateExprToInt(RHSInt, RHS, C) && RHSInt == 0;
      bool LHSMax = isMaxAmplExpr(LHS, C);
      bool RHSMax = isMaxAmplExpr(RHS, C);

      if (Op == BO_GT) {
        // maxAmpl > 0
        if (LHSMax && RHSZero)
          return true;
      } else if (Op == BO_NE) {
        // maxAmpl != 0  or  0 != maxAmpl
        if ((LHSMax && RHSZero) || (RHSMax && LHSZero))
          return true;
      } else if (Op == BO_LT) {
        // 0 < maxAmpl
        if (LHSZero && RHSMax)
          return true;
      }
    }
  }

  // Handle !(maxAmpl == 0)
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const BinaryOperator *SubBO = dyn_cast<BinaryOperator>(Sub)) {
        if (SubBO->getOpcode() == BO_EQ) {
          const Expr *LHS = SubBO->getLHS()->IgnoreParenImpCasts();
          const Expr *RHS = SubBO->getRHS()->IgnoreParenImpCasts();

          llvm::APSInt LHSInt, RHSInt;
          bool LHSZero = EvaluateExprToInt(LHSInt, LHS, C) && LHSInt == 0;
          bool RHSZero = EvaluateExprToInt(RHSInt, RHS, C) && RHSInt == 0;
          bool LHSMax = isMaxAmplExpr(LHS, C);
          bool RHSMax = isMaxAmplExpr(RHS, C);

          if ((LHSMax && RHSZero) || (RHSMax && LHSZero))
            return true;
        }
      }
    }
  }

  // Implicit boolean check: if (maxAmpl)
  if (isMaxAmplExpr(E, C))
    return true;

  return false;
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO,
                                    CheckerContext &C) const {
  if (!BO)
    return;

  if (BO->getOpcode() != BO_Div)
    return;

  const Expr *Denom = BO->getRHS();
  if (!Denom)
    return;

  Denom = Denom->IgnoreParenImpCasts();
  if (!isMaxAmplExpr(Denom, C))
    return;

  const IfStmt *EnclosingIf = findSpecificTypeInParents<IfStmt>(BO, C);
  if (!EnclosingIf) {
    reportDivByZero(BO, C);
    return;
  }

  const Expr *Cond = EnclosingIf->getCond();
  if (!containsMaxAmplZeroCheck(Cond, C))
    reportDivByZero(BO, C);
}

void SAGenTestChecker::reportDivByZero(const BinaryOperator *BO,
                                       CheckerContext &C) const {
  if (!BT)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Division by zero: maxAmpl can be zero", N);
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects division by zero when maxAmpl is not checked for zero",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
