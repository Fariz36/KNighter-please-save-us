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
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper: get VarDecl from a DeclRefExpr.
static const VarDecl *getVarDecl(const Expr *E) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<VarDecl>(DRE->getDecl());
  }
  return nullptr;
}

// Helper: flatten && chain in left-to-right order.
static void flattenLAnd(const Expr *E, SmallVectorImpl<const Expr *> &Ops) {
  if (!E) return;
  E = E->IgnoreParenImpCasts();
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      flattenLAnd(BO->getLHS(), Ops);
      flattenLAnd(BO->getRHS(), Ops);
      return;
    }
  }
  Ops.push_back(E);
}

// Helper: check if an expression evaluates to integer zero.
static bool isZeroConstant(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  llvm::APSInt Val;
  if (!EvaluateExprToInt(Val, E, C))
    return false;
  return Val == 0;
}

// Helper: detect ptr[N] with N >= 1.
static bool isDangerousSubscript(const Expr *E, const VarDecl *&Ptr,
                                 CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E);
  if (!ASE) return false;
  const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
  const Expr *IdxE = ASE->getIdx()->IgnoreParenImpCasts();
  const VarDecl *VD = getVarDecl(Base);
  if (!VD) return false;
  llvm::APSInt Idx;
  if (!EvaluateExprToInt(Idx, IdxE, C))
    return false;
  if (Idx.getSExtValue() < 1)
    return false;
  Ptr = VD;
  return true;
}

// Helper: recognize a guard on a variable: var, var != 0, var != '\0'.
static const VarDecl *getGuardVar(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();

  if (const VarDecl *VD = getVarDecl(E))
    return VD;

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(E);
  if (!BO) return nullptr;
  if (BO->getOpcode() != BO_NE) return nullptr;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  const VarDecl *LVD = getVarDecl(LHS);
  const VarDecl *RVD = getVarDecl(RHS);
  if (LVD && isZeroConstant(RHS, C))
    return LVD;
  if (RVD && isZeroConstant(LHS, C))
    return RVD;
  return nullptr;
}

// Helper: recognize ptr[N] == sep or ptr[N] != sep with N >= 1.
static bool getComparedSep(const Expr *E, const VarDecl *&Ptr,
                           const VarDecl *&Sep, CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(E);
  if (!BO) return false;
  if (BO->getOpcode() != BO_EQ && BO->getOpcode() != BO_NE)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  const VarDecl *LHSVar = nullptr;
  const VarDecl *RHSVar = nullptr;
  if (isDangerousSubscript(LHS, LHSVar, C)) {
    const VarDecl *RVar = getVarDecl(RHS);
    if (RVar) {
      Ptr = LHSVar;
      Sep = RVar;
      return true;
    }
  }
  if (isDangerousSubscript(RHS, RHSVar, C)) {
    const VarDecl *LVar = getVarDecl(LHS);
    if (LVar) {
      Ptr = RHSVar;
      Sep = LVar;
      return true;
    }
  }
  return false;
}

// Helper: check if expression is ptr[0] or *ptr.
static bool isPtr0Expr(const Expr *E, const VarDecl *Ptr, CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    const VarDecl *BaseVar = getVarDecl(ASE->getBase()->IgnoreParenImpCasts());
    if (BaseVar != Ptr) return false;
    llvm::APSInt Idx;
    if (!EvaluateExprToInt(Idx, ASE->getIdx()->IgnoreParenImpCasts(), C))
      return false;
    return Idx.getSExtValue() == 0;
  }
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      const VarDecl *SubVar = getVarDecl(UO->getSubExpr()->IgnoreParenImpCasts());
      return SubVar == Ptr;
    }
  }
  return false;
}

// Helper: check if statement assigns sep = ptr[0] (or *ptr).
static bool isSepAssignFromPtr0(const Stmt *S, const VarDecl *Sep,
                                const VarDecl *Ptr, CheckerContext &C) {
  if (!S) return false;
  if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(D)) {
        if (VD == Sep && VD->hasInit()) {
          return isPtr0Expr(VD->getInit(), Ptr, C);
        }
      }
    }
    return false;
  }

  const Expr *E = dyn_cast<Expr>(S);
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Assign) return false;
  const VarDecl *LHSVar = getVarDecl(BO->getLHS()->IgnoreParenImpCasts());
  if (LHSVar != Sep) return false;
  return isPtr0Expr(BO->getRHS()->IgnoreParenImpCasts(), Ptr, C);
}

// Helper: check if statement increments Ptr (ptr++, ++ptr, ptr += 1, ptr = ptr + 1).
static bool isPtrIncrement(const Stmt *S, const VarDecl *Ptr, CheckerContext &C) {
  if (!S) return false;
  const Expr *E = dyn_cast<Expr>(S);
  if (!E) return false;
  E = E->IgnoreParenImpCasts();

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc) {
      const VarDecl *VD = getVarDecl(UO->getSubExpr()->IgnoreParenImpCasts());
      return VD == Ptr;
    }
  }

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(E);
  if (!BO) return false;

  // ptr += 1
  if (BO->getOpcode() == BO_AddAssign) {
    const VarDecl *LHS = getVarDecl(BO->getLHS()->IgnoreParenImpCasts());
    if (LHS != Ptr) return false;
    llvm::APSInt Val;
    if (EvaluateExprToInt(Val, BO->getRHS()->IgnoreParenImpCasts(), C))
      return Val.getSExtValue() == 1;
  }

  // ptr = ptr + 1
  if (BO->getOpcode() == BO_Assign) {
    const VarDecl *LHS = getVarDecl(BO->getLHS()->IgnoreParenImpCasts());
    if (LHS != Ptr) return false;
    const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
    if (const BinaryOperator *Add = dyn_cast<BinaryOperator>(RHS)) {
      if (Add->getOpcode() == BO_Add) {
        const VarDecl *AddLHS = getVarDecl(Add->getLHS()->IgnoreParenImpCasts());
        const VarDecl *AddRHS = getVarDecl(Add->getRHS()->IgnoreParenImpCasts());
        if (AddLHS == Ptr) {
          llvm::APSInt Val;
          if (EvaluateExprToInt(Val, Add->getRHS()->IgnoreParenImpCasts(), C))
            return Val.getSExtValue() == 1;
        }
        if (AddRHS == Ptr) {
          llvm::APSInt Val;
          if (EvaluateExprToInt(Val, Add->getLHS()->IgnoreParenImpCasts(), C))
            return Val.getSExtValue() == 1;
        }
      }
    }
  }
  return false;
}

// Helper: check if expression is a call to strchr.
static bool isStrchrCall(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  const CallExpr *CE = dyn_cast<CallExpr>(E);
  if (!CE) return false;
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD) return false;
  return FD->getName() == "strchr";
}

// Helper: check if Ptr is initialized from strchr.
static bool isPtrFromStrchr(const VarDecl *Ptr, CheckerContext &C) {
  if (Ptr->hasInit()) {
    return isStrchrCall(Ptr->getInit(), C);
  }
  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NUL check", "Logic Error")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  bool isSepFromPtr0(const VarDecl *Sep, const VarDecl *Ptr,
                     const Stmt *Condition, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond) return;
  Cond = Cond->IgnoreParenImpCasts();

  SmallVector<const Expr *, 8> Ops;
  flattenLAnd(Cond, Ops);
  if (Ops.size() < 2) return;

  llvm::SmallPtrSet<const VarDecl *, 8> Guarded;
  for (const Expr *Op : Ops) {
    if (const VarDecl *V = getGuardVar(Op, C)) {
      Guarded.insert(V);
      continue;
    }

    const VarDecl *Ptr = nullptr;
    const VarDecl *Sep = nullptr;
    if (getComparedSep(Op, Ptr, Sep, C)) {
      if (!Guarded.contains(Sep)) {
        if (isSepFromPtr0(Sep, Ptr, Condition, C)) {
          ExplodedNode *N = C.generateNonFatalErrorNode();
          if (!N) return;
          auto Report = std::make_unique<PathSensitiveBugReport>(
              *BT, "Missing NUL check before reading past delimiter", N);
          Report->addRange(Op->getSourceRange());
          C.emitReport(std::move(Report));
          return;
        }
      }
    }
  }
}

bool SAGenTestChecker::isSepFromPtr0(const VarDecl *Sep, const VarDecl *Ptr,
                                     const Stmt *Condition,
                                     CheckerContext &C) const {
  if (!Sep || !Ptr) return false;

  if (!isPtrFromStrchr(Ptr, C))
    return false;

  const IfStmt *If = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!If) return false;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(If, C);
  if (!CS) return false;

  bool FoundInc = false;
  bool ValidAssign = false;

  for (const Stmt *S : CS->body()) {
    if (S == If) {
      return ValidAssign;
    }
    if (isSepAssignFromPtr0(S, Sep, Ptr, C)) {
      if (FoundInc)
        ValidAssign = true;
    }
    if (isPtrIncrement(S, Ptr, C)) {
      FoundInc = true;
    }
  }

  return false;
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NUL check before reading past delimiter",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
