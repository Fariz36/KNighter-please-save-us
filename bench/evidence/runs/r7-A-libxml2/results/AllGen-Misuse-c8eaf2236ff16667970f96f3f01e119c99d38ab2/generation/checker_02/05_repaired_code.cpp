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
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool isLiteralZero(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue() == 0;
  return false;
}

static bool isLiteralOne(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue() == 1;
  return false;
}

static bool isMaxAmplExpr(const Expr *E, StringRef Name) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    const ValueDecl *VD = DRE->getDecl();
    return VD && VD->getNameAsString() == Name.str();
  }

  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    const ValueDecl *VD = ME->getMemberDecl();
    return VD && VD->getNameAsString() == Name.str();
  }

  return false;
}

static bool branchReturns(const Stmt *S) {
  if (!S)
    return false;

  if (isa<ReturnStmt>(S))
    return true;

  if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
    for (const Stmt *Child : CS->body()) {
      if (isa<ReturnStmt>(Child))
        return true;
    }
  }

  return false;
}

static bool isZeroRejectionCondition(const Expr *Cond, StringRef ParamName) {
  if (!Cond)
    return false;

  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      return isMaxAmplExpr(Sub, ParamName);
    }
  }

  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return false;

  BinaryOperator::Opcode Op = BO->getOpcode();
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  bool LMax = isMaxAmplExpr(LHS, ParamName);
  bool RMax = isMaxAmplExpr(RHS, ParamName);

  switch (Op) {
  case BO_EQ:
    return (LMax && isLiteralZero(RHS)) || (RMax && isLiteralZero(LHS));
  case BO_LE:
    return LMax && isLiteralZero(RHS); // maxAmpl <= 0
  case BO_GE:
    return isLiteralZero(LHS) && RMax; // 0 >= maxAmpl
  case BO_LT:
    return LMax && isLiteralOne(RHS); // maxAmpl < 1
  case BO_GT:
    return isLiteralOne(LHS) && RMax; // 1 > maxAmpl
  default:
    return false;
  }
}

static bool isZeroRejectionIf(const IfStmt *IS, StringRef ParamName) {
  if (!IS)
    return false;

  if (!isZeroRejectionCondition(IS->getCond(), ParamName))
    return false;

  return branchReturns(IS->getThen());
}

static bool containsAssignmentToMaxAmpl(const Stmt *S, StringRef FieldName) {
  if (!S)
    return false;

  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (const auto *ME = dyn_cast<MemberExpr>(LHS)) {
        const ValueDecl *VD = ME->getMemberDecl();
        if (VD && VD->getNameAsString() == FieldName.str())
          return true;
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (containsAssignmentToMaxAmpl(Child, FieldName))
      return true;
  }

  return false;
}

static bool hasNonZeroGuard(const Expr *Cond, StringRef Name) {
  if (!Cond)
    return false;

  Cond = Cond->IgnoreParenImpCasts();

  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return false;

  BinaryOperator::Opcode Op = BO->getOpcode();
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  bool LMax = isMaxAmplExpr(LHS, Name);
  bool RMax = isMaxAmplExpr(RHS, Name);

  switch (Op) {
  case BO_GT:
    if (LMax && isLiteralZero(RHS)) // maxAmpl > 0
      return true;
    break;
  case BO_NE:
    if (LMax && isLiteralZero(RHS)) // maxAmpl != 0
      return true;
    if (RMax && isLiteralZero(LHS)) // 0 != maxAmpl
      return true;
    break;
  case BO_GE:
    if (LMax && isLiteralOne(RHS)) // maxAmpl >= 1
      return true;
    break;
  case BO_LT:
    if (isLiteralZero(LHS) && RMax) // 0 < maxAmpl
      return true;
    break;
  case BO_LE:
    if (isLiteralOne(LHS) && RMax) // 1 <= maxAmpl
      return true;
    break;
  case BO_LAnd:
  case BO_LOr:
    if (hasNonZeroGuard(LHS, Name) || hasNonZeroGuard(RHS, Name))
      return true;
    break;
  default:
    break;
  }

  return false;
}

class SAGenTestChecker
    : public Checker<check::ASTDecl<FunctionDecl>,
                     check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;
  mutable bool SetterValidatesZero = false;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Division by zero", "Arithmetic")) {}

  void checkASTDecl(const FunctionDecl *FD, AnalysisManager &Mgr,
                    BugReporter &BR) const;

  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
};

void SAGenTestChecker::checkASTDecl(const FunctionDecl *FD, AnalysisManager &,
                                    BugReporter &) const {
  if (!FD || !FD->hasBody())
    return;

  if (FD->getNameAsString() != "xmlCtxtSetMaxAmplification")
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  bool GuardSeen = false;

  if (const auto *CS = dyn_cast<CompoundStmt>(Body)) {
    for (const Stmt *Child : CS->body()) {
      if (const auto *IS = dyn_cast<IfStmt>(Child)) {
        if (isZeroRejectionIf(IS, "maxAmpl")) {
          GuardSeen = true;
          continue;
        }
      }

      if (containsAssignmentToMaxAmpl(Child, "maxAmpl")) {
        if (GuardSeen)
          SetterValidatesZero = true;
        return;
      }
    }
  }
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO,
                                    CheckerContext &C) const {
  if (!BO || BO->getOpcode() != BO_Div)
    return;

  const Expr *Div = BO->getRHS()->IgnoreParenImpCasts();
  if (!isMaxAmplExpr(Div, "maxAmpl"))
    return;

  bool HasGuard = false;

  if (const IfStmt *IS = findSpecificTypeInParents<IfStmt>(BO, C)) {
    HasGuard = hasNonZeroGuard(IS->getCond(), "maxAmpl");
  }

  if (HasGuard || SetterValidatesZero)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Division by zero: maxAmpl may be 0", N);
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects division by maxAmpl when it may be zero",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
