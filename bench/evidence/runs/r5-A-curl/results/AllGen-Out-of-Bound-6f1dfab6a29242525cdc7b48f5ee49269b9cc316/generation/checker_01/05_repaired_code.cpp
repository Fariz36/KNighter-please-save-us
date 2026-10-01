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
#include "llvm/ADT/APSInt.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool getConstantInt(const Expr *E, llvm::APSInt &Val, CheckerContext &C) {
  E = E->IgnoreParenImpCasts();
  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
    Val = IL->getValue();
    return true;
  }
  return EvaluateExprToInt(Val, E, C);
}

static bool isDeclRefTo(const Expr *E, const ValueDecl *VD) {
  if (!E || !VD)
    return false;
  E = E->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
  return DRE && DRE->getDecl() == VD;
}

static bool isArraySubscriptOfPtrWithIndex(const Expr *E,
                                           const ValueDecl *PtrVD, int Index,
                                           CheckerContext &C) {
  if (!E || !PtrVD)
    return false;
  const ArraySubscriptExpr *ASE =
      dyn_cast<ArraySubscriptExpr>(E->IgnoreParenImpCasts());
  if (!ASE)
    return false;
  if (!isDeclRefTo(ASE->getBase(), PtrVD))
    return false;
  llvm::APSInt Idx;
  if (!getConstantInt(ASE->getIdx(), Idx, C))
    return false;
  return Idx.getSExtValue() == Index;
}

static bool isArraySubscriptOfPtrWithIndexGE(const ArraySubscriptExpr *ASE,
                                             const ValueDecl *PtrVD,
                                             int MinIndex,
                                             CheckerContext &C) {
  if (!ASE || !PtrVD)
    return false;
  if (!isDeclRefTo(ASE->getBase(), PtrVD))
    return false;
  llvm::APSInt Idx;
  if (!getConstantInt(ASE->getIdx(), Idx, C))
    return false;
  return Idx.getSExtValue() >= MinIndex;
}

static bool isComparePtrIndexWithSep(const BinaryOperator *BO,
                                     const ValueDecl *PtrVD,
                                     const ValueDecl *SepVD, int Index,
                                     CheckerContext &C) {
  if (!BO || BO->getOpcode() != BO_EQ)
    return false;
  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  return (isArraySubscriptOfPtrWithIndex(LHS, PtrVD, Index, C) &&
          isDeclRefTo(RHS, SepVD)) ||
         (isArraySubscriptOfPtrWithIndex(RHS, PtrVD, Index, C) &&
          isDeclRefTo(LHS, SepVD));
}

static bool isSepGuard(const Expr *E, const ValueDecl *SepVD,
                       CheckerContext &C) {
  if (!E || !SepVD)
    return false;
  E = E->IgnoreParenImpCasts();
  if (isDeclRefTo(E, SepVD))
    return true;
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_NE)
    return false;
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  auto isZeroConst = [](const Expr *E) -> bool {
    if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E))
      return IL->getValue().isZero();
    if (const CharacterLiteral *CL = dyn_cast<CharacterLiteral>(E))
      return CL->getValue() == 0;
    return false;
  };
  bool LHSIsSep = isDeclRefTo(LHS, SepVD);
  bool RHSIsSep = isDeclRefTo(RHS, SepVD);
  bool LHSIsZero = isZeroConst(LHS);
  bool RHSIsZero = isZeroConst(RHS);
  return (LHSIsSep && RHSIsZero) || (RHSIsSep && LHSIsZero);
}

static void analyzeCondition(const Expr *E, const ValueDecl *SepVD,
                             const ValueDecl *PtrVD, bool &HasPtr1EqSep,
                             bool &HasPtr2EqSep, bool &HasPtr3Access,
                             bool &HasSepGuard, bool IsBoolContext,
                             CheckerContext &C) {
  if (!E)
    return;
  E = E->IgnoreParens();

  if (IsBoolContext && isSepGuard(E, SepVD, C)) {
    HasSepGuard = true;
  }

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      analyzeCondition(BO->getLHS(), SepVD, PtrVD, HasPtr1EqSep, HasPtr2EqSep,
                       HasPtr3Access, HasSepGuard, true, C);
      analyzeCondition(BO->getRHS(), SepVD, PtrVD, HasPtr1EqSep, HasPtr2EqSep,
                       HasPtr3Access, HasSepGuard, true, C);
      return;
    }
    if (BO->getOpcode() == BO_EQ) {
      if (isComparePtrIndexWithSep(BO, PtrVD, SepVD, 1, C))
        HasPtr1EqSep = true;
      if (isComparePtrIndexWithSep(BO, PtrVD, SepVD, 2, C))
        HasPtr2EqSep = true;
    }
    analyzeCondition(BO->getLHS(), SepVD, PtrVD, HasPtr1EqSep, HasPtr2EqSep,
                     HasPtr3Access, HasSepGuard, false, C);
    analyzeCondition(BO->getRHS(), SepVD, PtrVD, HasPtr1EqSep, HasPtr2EqSep,
                     HasPtr3Access, HasSepGuard, false, C);
    return;
  }

  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    if (isArraySubscriptOfPtrWithIndexGE(ASE, PtrVD, 3, C)) {
      HasPtr3Access = true;
    }
    analyzeCondition(ASE->getBase(), SepVD, PtrVD, HasPtr1EqSep, HasPtr2EqSep,
                     HasPtr3Access, HasSepGuard, false, C);
    analyzeCondition(ASE->getIdx(), SepVD, PtrVD, HasPtr1EqSep, HasPtr2EqSep,
                     HasPtr3Access, HasSepGuard, false, C);
    return;
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child))
      analyzeCondition(ChildE, SepVD, PtrVD, HasPtr1EqSep, HasPtr2EqSep,
                       HasPtr3Access, HasSepGuard, false, C);
  }
}

static bool findSepAssignment(const CompoundStmt *CS, const IfStmt *IS,
                              const ValueDecl *&SepVD, const ValueDecl *&PtrVD,
                              CheckerContext &C) {
  if (!CS)
    return false;
  for (const Stmt *S : CS->body()) {
    if (S == IS)
      break;

    const Expr *E = dyn_cast<Expr>(S);
    if (E) {
      E = E->IgnoreParenImpCasts();
      if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
        if (BO->getOpcode() == BO_Assign) {
          const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
          const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS);
          if (!DRE)
            continue;
          const ValueDecl *VD = DRE->getDecl();
          const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
          if (const ArraySubscriptExpr *ASE =
                  dyn_cast<ArraySubscriptExpr>(RHS)) {
            const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
            const DeclRefExpr *BaseDRE = dyn_cast<DeclRefExpr>(Base);
            if (!BaseDRE)
              continue;
            llvm::APSInt Idx;
            if (!getConstantInt(ASE->getIdx(), Idx, C))
              continue;
            if (Idx.getSExtValue() != 0)
              continue;
            SepVD = VD;
            PtrVD = BaseDRE->getDecl();
            return true;
          }
        }
      }
    } else if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
      for (const Decl *D : DS->decls()) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(D)) {
          if (const Expr *Init = VD->getInit()) {
            const Expr *InitE = Init->IgnoreParenImpCasts();
            if (const ArraySubscriptExpr *ASE =
                    dyn_cast<ArraySubscriptExpr>(InitE)) {
              const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
              const DeclRefExpr *BaseDRE = dyn_cast<DeclRefExpr>(Base);
              if (!BaseDRE)
                continue;
              llvm::APSInt Idx;
              if (!getConstantInt(ASE->getIdx(), Idx, C))
                continue;
              if (Idx.getSExtValue() != 0)
                continue;
              SepVD = VD;
              PtrVD = BaseDRE->getDecl();
              continue;
            }
          }
        }
      }
    }
  }
  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NUL terminator check",
                       "Out-of-bounds read")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
  if (!CS)
    return;

  const ValueDecl *SepVD = nullptr;
  const ValueDecl *PtrVD = nullptr;
  if (!findSepAssignment(CS, IS, SepVD, PtrVD, C))
    return;
  if (!SepVD || !PtrVD)
    return;

  bool HasPtr1EqSep = false;
  bool HasPtr2EqSep = false;
  bool HasPtr3Access = false;
  bool HasSepGuard = false;

  analyzeCondition(CondE, SepVD, PtrVD, HasPtr1EqSep, HasPtr2EqSep,
                   HasPtr3Access, HasSepGuard, true, C);

  if (HasPtr1EqSep && HasPtr2EqSep && HasPtr3Access && !HasSepGuard) {
    if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
      auto report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Missing check for NUL terminator before fixed-offset lookahead",
          N);
      report->addRange(CondE->getSourceRange());
      C.emitReport(std::move(report));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NUL terminator check before fixed-offset lookahead",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
