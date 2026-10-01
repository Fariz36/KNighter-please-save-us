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
#include "llvm/Support/Casting.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool isIntegerLiteral(const Expr *E, unsigned Index) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue() == Index;
  return false;
}

static const ArraySubscriptExpr *getArraySubscript(const Expr *E,
                                                   unsigned Index) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  const auto *ASE = dyn_cast<ArraySubscriptExpr>(E);
  if (!ASE)
    return nullptr;
  if (!isIntegerLiteral(ASE->getIdx(), Index))
    return nullptr;
  return ASE;
}

static bool isSepRef(const Expr *E, const ValueDecl *SepDecl) {
  if (!E || !SepDecl)
    return false;
  E = E->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  return DRE && DRE->getDecl() == SepDecl;
}

static bool sameExpr(const Expr *A, const Expr *B) {
  if (!A || !B)
    return false;

  A = A->IgnoreParenImpCasts();
  B = B->IgnoreParenImpCasts();

  if (A == B)
    return true;

  if (const auto *DREA = dyn_cast<DeclRefExpr>(A)) {
    if (const auto *DREB = dyn_cast<DeclRefExpr>(B))
      return DREA->getDecl() == DREB->getDecl();
  }

  if (const auto *MEA = dyn_cast<MemberExpr>(A)) {
    if (const auto *MEB = dyn_cast<MemberExpr>(B))
      return MEA->getMemberDecl() == MEB->getMemberDecl() &&
             sameExpr(MEA->getBase(), MEB->getBase());
  }

  return false;
}

static bool findEqWithIndex(const Expr *E, unsigned Index,
                            const ValueDecl *&SepDecl,
                            const Expr *&Base) {
  if (!E)
    return false;

  E = E->IgnoreParens();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

      const ArraySubscriptExpr *Sub = getArraySubscript(L, Index);
      const Expr *Other = R;
      if (!Sub) {
        Sub = getArraySubscript(R, Index);
        Other = L;
      }

      if (Sub) {
        Other = Other->IgnoreParenImpCasts();
        if (const auto *DRE = dyn_cast<DeclRefExpr>(Other)) {
          if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
            if (VD->getType()->isIntegerType()) {
              SepDecl = VD;
              Base = Sub->getBase()->IgnoreParenImpCasts();
              return true;
            }
          }
        }
      }
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast<Expr>(Child)) {
      if (findEqWithIndex(CE, Index, SepDecl, Base))
        return true;
    }
  }

  return false;
}

static bool hasEqWithIndexAndSepBase(const Expr *E, unsigned Index,
                                     const ValueDecl *SepDecl,
                                     const Expr *Base) {
  if (!E)
    return false;

  E = E->IgnoreParens();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

      const ArraySubscriptExpr *Sub = getArraySubscript(L, Index);
      const Expr *Other = R;
      if (!Sub) {
        Sub = getArraySubscript(R, Index);
        Other = L;
      }

      if (Sub && isSepRef(Other, SepDecl) &&
          sameExpr(Sub->getBase(), Base))
        return true;
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast<Expr>(Child)) {
      if (hasEqWithIndexAndSepBase(CE, Index, SepDecl, Base))
        return true;
    }
  }

  return false;
}

static bool hasIndexUse(const Expr *E, unsigned Index, const Expr *Base) {
  if (!E)
    return false;

  E = E->IgnoreParens();

  if (const auto *ASE = getArraySubscript(E, Index)) {
    if (sameExpr(ASE->getBase(), Base))
      return true;
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast<Expr>(Child)) {
      if (hasIndexUse(CE, Index, Base))
        return true;
    }
  }

  return false;
}

static bool isZeroConstant(const Expr *E, CheckerContext &C) {
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, E, C))
    return EvalRes == 0;
  return false;
}

static bool hasSepGuard(const Expr *E, const ValueDecl *SepDecl,
                        CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParens();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    // sep != 0  /  sep != '\0'
    if (BO->getOpcode() == BO_NE) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      if ((isSepRef(L, SepDecl) && isZeroConstant(R, C)) ||
          (isSepRef(R, SepDecl) && isZeroConstant(L, C)))
        return true;
    }

    // sep && ...
    if (BO->getOpcode() == BO_LAnd) {
      if (isSepRef(BO->getLHS(), SepDecl))
        return true;
    }
  }

  // !(sep == 0)  /  !(sep == '\0')
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *BO = dyn_cast<BinaryOperator>(Sub)) {
        if (BO->getOpcode() == BO_EQ) {
          const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
          const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
          if ((isSepRef(L, SepDecl) && isZeroConstant(R, C)) ||
              (isSepRef(R, SepDecl) && isZeroConstant(L, C)))
            return true;
        }
      }
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *CE = dyn_cast<Expr>(Child)) {
      if (hasSepGuard(CE, SepDecl, C))
        return true;
    }
  }

  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NUL check before lookahead",
                       "Out-of-bounds read")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  Cond = Cond->IgnoreParens();

  const ValueDecl *SepDecl = nullptr;
  const Expr *Base = nullptr;

  // Recognize: ptr[1] == sep
  if (!findEqWithIndex(Cond, 1, SepDecl, Base))
    return;
  if (!SepDecl || !Base)
    return;

  // Recognize: ptr[2] == sep, with the same sep and same base pointer.
  if (!hasEqWithIndexAndSepBase(Cond, 2, SepDecl, Base))
    return;

  // Recognize lookahead use of ptr[3], e.g. ISDIGIT(ptr[3]).
  if (!hasIndexUse(Cond, 3, Base))
    return;

  // If sep is already guarded against being '\0', do not report.
  if (hasSepGuard(Cond, SepDecl, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing NUL check before lookahead", N);
  Report->addRange(Cond->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NUL check before delimiter lookahead",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
