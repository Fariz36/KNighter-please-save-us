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
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/Casting.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read", "Memory safety")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportBug(const Expr *E, CheckerContext &C) const;
};

static bool getDeclRefVar(const Expr *E, const VarDecl *&VD) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *V = dyn_cast<VarDecl>(DRE->getDecl())) {
      VD = V;
      return true;
    }
  }
  return false;
}

static bool getArraySubscriptBaseVarIndex(const Expr *E, const VarDecl *&VD,
                                          int64_t Index, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E);
  if (!ASE)
    return false;

  const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base);
  if (!DRE)
    return false;

  const VarDecl *V = dyn_cast<VarDecl>(DRE->getDecl());
  if (!V)
    return false;

  llvm::APSInt IdxVal;
  if (!EvaluateExprToInt(IdxVal, ASE->getIdx(), C))
    return false;

  if (IdxVal.getSExtValue() != Index)
    return false;

  VD = V;
  return true;
}

static bool getSepAndPtrFromComparison(const Expr *E, const VarDecl *&SepVD,
                                       const VarDecl *&PtrVD,
                                       CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_EQ)
    return false;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();

  const VarDecl *TmpPtr = nullptr;
  const VarDecl *TmpSep = nullptr;

  // ptr[1] == sep
  if (getArraySubscriptBaseVarIndex(LHS, TmpPtr, 1, C) &&
      getDeclRefVar(RHS, TmpSep)) {
    PtrVD = TmpPtr;
    SepVD = TmpSep;
    return true;
  }

  // sep == ptr[1]
  if (getArraySubscriptBaseVarIndex(RHS, TmpPtr, 1, C) &&
      getDeclRefVar(LHS, TmpSep)) {
    PtrVD = TmpPtr;
    SepVD = TmpSep;
    return true;
  }

  return false;
}

static bool isZeroValue(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  llvm::APSInt Val;
  if (!EvaluateExprToInt(Val, E, C))
    return false;

  return Val.isZero();
}

static bool isGuardForVar(const Expr *E, const VarDecl *VD,
                          CheckerContext &C) {
  if (!E || !VD)
    return false;

  E = E->IgnoreParenImpCasts();

  const VarDecl *V = nullptr;
  if (getDeclRefVar(E, V) && V == VD)
    return true;

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_NE)
    return false;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();

  if (getDeclRefVar(LHS, V) && V == VD && isZeroValue(RHS, C))
    return true;

  if (getDeclRefVar(RHS, V) && V == VD && isZeroValue(LHS, C))
    return true;

  return false;
}

static bool isAssignmentToVar(const Stmt *S, const VarDecl *SepVD) {
  if (!S || !SepVD)
    return false;

  if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      const VarDecl *VD = dyn_cast<VarDecl>(D);
      if (VD == SepVD && VD->hasInit())
        return true;
    }
    return false;
  }

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || BO->getOpcode() != BO_Assign)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS);
  if (!DRE)
    return false;

  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  return VD == SepVD;
}

static bool isAssignmentFromPtrZero(const Stmt *S, const VarDecl *SepVD,
                                    const VarDecl *&PtrVD,
                                    CheckerContext &C) {
  if (!S || !SepVD)
    return false;

  if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      const VarDecl *VD = dyn_cast<VarDecl>(D);
      if (VD == SepVD && VD->hasInit()) {
        const VarDecl *TmpPtr = nullptr;
        if (getArraySubscriptBaseVarIndex(VD->getInit(), TmpPtr, 0, C)) {
          PtrVD = TmpPtr;
          return true;
        }
      }
    }
    return false;
  }

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || BO->getOpcode() != BO_Assign)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS);
  if (!DRE)
    return false;

  const VarDecl *LHSVD = dyn_cast<VarDecl>(DRE->getDecl());
  if (LHSVD != SepVD)
    return false;

  const VarDecl *TmpPtr = nullptr;
  if (getArraySubscriptBaseVarIndex(BO->getRHS(), TmpPtr, 0, C)) {
    PtrVD = TmpPtr;
    return true;
  }

  return false;
}

static bool findPrecedingAssignment(const CompoundStmt *CS, const Stmt *IfS,
                                    const VarDecl *SepVD, const VarDecl *&PtrVD,
                                    CheckerContext &C) {
  if (!CS || !IfS || !SepVD)
    return false;

  const Stmt *LastAssign = nullptr;
  for (const Stmt *S : CS->body()) {
    if (S == IfS)
      break;
    if (isAssignmentToVar(S, SepVD))
      LastAssign = S;
  }

  if (!LastAssign)
    return false;

  return isAssignmentFromPtrZero(LastAssign, SepVD, PtrVD, C);
}

static void flattenAnd(const Expr *E, llvm::SmallVectorImpl<const Expr *> &Ops) {
  if (!E)
    return;

  E = E->IgnoreParenImpCasts();
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      flattenAnd(BO->getLHS(), Ops);
      flattenAnd(BO->getRHS(), Ops);
      return;
    }
  }

  Ops.push_back(E);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenImpCasts();
  const BinaryOperator *TopBO = dyn_cast<BinaryOperator>(CondE);
  if (!TopBO || TopBO->getOpcode() != BO_LAnd)
    return;

  llvm::SmallVector<const Expr *, 8> Ops;
  flattenAnd(CondE, Ops);

  for (unsigned i = 0; i < Ops.size(); ++i) {
    const VarDecl *SepVD = nullptr;
    const VarDecl *PtrVD = nullptr;
    if (!getSepAndPtrFromComparison(Ops[i], SepVD, PtrVD, C))
      continue;

    bool Guarded = false;
    for (unsigned j = 0; j < i; ++j) {
      if (isGuardForVar(Ops[j], SepVD, C)) {
        Guarded = true;
        break;
      }
    }

    if (Guarded)
      return;

    const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
    if (!IS)
      return;

    const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
    if (!CS)
      return;

    const VarDecl *AssignPtr = nullptr;
    if (!findPrecedingAssignment(CS, IS, SepVD, AssignPtr, C))
      return;

    if (AssignPtr != PtrVD)
      return;

    reportBug(Ops[i], C);
    return;
  }
}

void SAGenTestChecker::reportBug(const Expr *E, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing NUL check before lookahead read", N);
  report->addRange(E->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NUL check before lookahead read (out-of-bounds read)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
