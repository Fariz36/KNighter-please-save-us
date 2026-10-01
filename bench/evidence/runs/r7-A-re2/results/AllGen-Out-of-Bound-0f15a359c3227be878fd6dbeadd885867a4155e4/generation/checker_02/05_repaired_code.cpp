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
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/OperatorKinds.h"
#include "llvm/Support/Casting.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static const ValueDecl *getValueDeclFromExpr(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E))
    return DRE->getDecl();
  if (const MemberExpr *ME = dyn_cast<MemberExpr>(E))
    return ME->getMemberDecl();
  return nullptr;
}

static bool isCountMinusOne(const Expr *Index, const ValueDecl *&CountDecl,
                            CheckerContext &C) {
  if (!Index)
    return false;

  Index = Index->IgnoreParenImpCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Index);
  if (!BO || BO->getOpcode() != BO_Sub)
    return false;

  llvm::APSInt One;
  if (!EvaluateExprToInt(One, BO->getRHS()->IgnoreParenImpCasts(), C))
    return false;

  if (One.getLimitedValue() != 1)
    return false;

  const ValueDecl *VD = getValueDeclFromExpr(BO->getLHS());
  if (!VD)
    return false;

  CountDecl = VD;
  return true;
}

static bool isPositiveGuard(const Expr *Cond, const ValueDecl *CountDecl,
                            CheckerContext &C) {
  if (!Cond)
    return false;
  Cond = Cond->IgnoreParenImpCasts();

  // Bare `count` is equivalent to `count != 0`.
  if (getValueDeclFromExpr(Cond) == CountDecl)
    return true;

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return false;

  BinaryOperator::Opcode Op = BO->getOpcode();
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  const ValueDecl *LVD = getValueDeclFromExpr(LHS);
  const ValueDecl *RVD = getValueDeclFromExpr(RHS);

  llvm::APSInt IntVal;
  if (LVD == CountDecl) {
    if (!EvaluateExprToInt(IntVal, RHS, C))
      return false;
    switch (Op) {
    case BO_GT:
      return IntVal.getLimitedValue() == 0; // count > 0
    case BO_GE:
      return IntVal.getLimitedValue() == 1; // count >= 1
    case BO_NE:
      return IntVal.getLimitedValue() == 0; // count != 0
    default:
      return false;
    }
  } else if (RVD == CountDecl) {
    if (!EvaluateExprToInt(IntVal, LHS, C))
      return false;
    switch (Op) {
    case BO_LT:
      return IntVal.getLimitedValue() == 0; // 0 < count
    case BO_LE:
      return IntVal.getLimitedValue() == 1; // 1 <= count
    default:
      return false;
    }
  }

  return false;
}

static bool isGuarded(const Stmt *Access, const ValueDecl *CountDecl,
                      CheckerContext &C) {
  if (!Access)
    return false;

  DynTypedNode Current = DynTypedNode::create(*Access);
  while (true) {
    auto Parents = C.getASTContext().getParentMapContext().getParents(Current);
    if (Parents.begin() == Parents.end())
      break;

    const DynTypedNode &Parent = *Parents.begin();

    if (const IfStmt *IS = Parent.get<IfStmt>()) {
      if (const Stmt *CurrentStmt = Current.get<Stmt>()) {
        if (IS->getThen() == CurrentStmt &&
            isPositiveGuard(IS->getCond(), CountDecl, C))
          return true;
      }
    }

    Current = Parent;
  }

  return false;
}

class SAGenTestChecker
    : public Checker<check::PreStmt<ArraySubscriptExpr>,
                     check::PreStmt<CXXOperatorCallExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Buffer underflow", "Memory Error")) {}

  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
  void checkPreStmt(const CXXOperatorCallExpr *OCE, CheckerContext &C) const;

private:
  void reportUnderflow(const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE,
                                    CheckerContext &C) const {
  const ValueDecl *CountDecl = nullptr;
  if (!isCountMinusOne(ASE->getIdx(), CountDecl, C))
    return;

  if (isGuarded(ASE, CountDecl, C))
    return;

  reportUnderflow(ASE, C);
}

void SAGenTestChecker::checkPreStmt(const CXXOperatorCallExpr *OCE,
                                    CheckerContext &C) const {
  if (OCE->getOperator() != OO_Subscript)
    return;

  if (OCE->getNumArgs() < 2)
    return;

  const ValueDecl *CountDecl = nullptr;
  if (!isCountMinusOne(OCE->getArg(1), CountDecl, C))
    return;

  if (isGuarded(OCE, CountDecl, C))
    return;

  reportUnderflow(OCE, C);
}

void SAGenTestChecker::reportUnderflow(const Stmt *S,
                                       CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Buffer underflow: accessing container[count-1] without checking count > 0",
      N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects container[count-1] buffer underflow when count may be zero",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
