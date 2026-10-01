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
#include "clang/AST/OperationKinds.h"
#include "llvm/ADT/APSInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static const VarDecl *getVarDeclFromExpr(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E))
    return dyn_cast<VarDecl>(DRE->getDecl());
  return nullptr;
}

static bool evaluateInt(const Expr *E, int64_t &Val, CheckerContext &C) {
  if (!E)
    return false;
  llvm::APSInt Res;
  if (EvaluateExprToInt(Res, E, C)) {
    Val = Res.getSExtValue();
    return true;
  }
  return false;
}

static bool matchPtrAccess(const Expr *E, const VarDecl *PtrVD,
                           int64_t &Offset, CheckerContext &C) {
  if (!E || !PtrVD || !PtrVD->getType()->isPointerType())
    return false;

  E = E->IgnoreParenImpCasts();

  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (getVarDeclFromExpr(Base) != PtrVD)
      return false;

    int64_t Idx = 0;
    if (!evaluateInt(ASE->getIdx(), Idx, C))
      return false;
    Offset = Idx;
    return true;
  }

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();

      if (getVarDeclFromExpr(Sub) == PtrVD) {
        Offset = 0;
        return true;
      }

      if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Sub)) {
        if (BO->getOpcode() == BO_Add) {
          const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
          const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

          if (getVarDeclFromExpr(L) == PtrVD) {
            int64_t Off = 0;
            if (evaluateInt(R, Off, C)) {
              Offset = Off;
              return true;
            }
          }

          if (getVarDeclFromExpr(R) == PtrVD) {
            int64_t Off = 0;
            if (evaluateInt(L, Off, C)) {
              Offset = Off;
              return true;
            }
          }
        }
      }
    }
  }

  return false;
}

static bool findDangerousSubscript(const Expr *E, const VarDecl *&PtrVD,
                                   int64_t &Offset, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base)) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (VD->getType()->isPointerType()) {
          int64_t Idx = 0;
          if (evaluateInt(ASE->getIdx(), Idx, C) && Idx >= 1) {
            PtrVD = VD;
            Offset = Idx;
            return true;
          }
        }
      }
    }
  }

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();

      if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Sub)) {
        if (BO->getOpcode() == BO_Add) {
          const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
          const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

          if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(L)) {
            if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
              if (VD->getType()->isPointerType()) {
                int64_t Off = 0;
                if (evaluateInt(R, Off, C) && Off >= 1) {
                  PtrVD = VD;
                  Offset = Off;
                  return true;
                }
              }
            }
          }

          if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(R)) {
            if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
              if (VD->getType()->isPointerType()) {
                int64_t Off = 0;
                if (evaluateInt(L, Off, C) && Off >= 1) {
                  PtrVD = VD;
                  Offset = Off;
                  return true;
                }
              }
            }
          }
        }
      }
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *CE = dyn_cast<Expr>(Child)) {
      if (findDangerousSubscript(CE, PtrVD, Offset, C))
        return true;
    }
  }

  return false;
}

static bool containsDangerousAccess(const Expr *E, const VarDecl *PtrVD,
                                    CheckerContext &C) {
  if (!E || !PtrVD)
    return false;

  E = E->IgnoreParenImpCasts();

  int64_t Off = 0;
  if (matchPtrAccess(E, PtrVD, Off, C) && Off >= 1)
    return true;

  for (const Stmt *Child : E->children()) {
    if (const Expr *CE = dyn_cast<Expr>(Child)) {
      if (containsDangerousAccess(CE, PtrVD, C))
        return true;
    }
  }

  return false;
}

static bool isGuardOnSep(const Expr *E, const VarDecl *SepVD,
                         const VarDecl *PtrVD, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (getVarDeclFromExpr(E) == SepVD)
    return true;

  int64_t Off = 0;
  if (matchPtrAccess(E, PtrVD, Off, C) && Off == 0)
    return true;

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(E);
  if (!BO)
    return false;

  BinaryOperator::Opcode Op = BO->getOpcode();
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  if (getVarDeclFromExpr(LHS) == SepVD ||
      getVarDeclFromExpr(RHS) == SepVD) {
    const Expr *Other = (getVarDeclFromExpr(LHS) == SepVD) ? RHS : LHS;
    int64_t Val = 0;
    if (evaluateInt(Other, Val, C)) {
      if (Op == BO_NE && Val == 0) return true;
      if (Op == BO_GT && Val == 0) return true;
      if (Op == BO_GE && Val == 1) return true;
      if (Op == BO_LT && Val == 0) return true;
      if (Op == BO_LE && Val == 1) return true;
    }
  }

  int64_t OffL = 0;
  int64_t OffR = 0;
  const Expr *PtrSide = nullptr;

  if (matchPtrAccess(LHS, PtrVD, OffL, C) && OffL == 0)
    PtrSide = LHS;
  else if (matchPtrAccess(RHS, PtrVD, OffR, C) && OffR == 0)
    PtrSide = RHS;

  if (PtrSide) {
    const Expr *Other = (PtrSide == LHS) ? RHS : LHS;
    int64_t Val = 0;
    if (evaluateInt(Other, Val, C)) {
      if (Op == BO_NE && Val == 0) return true;
      if (Op == BO_GT && Val == 0) return true;
      if (Op == BO_GE && Val == 1) return true;
      if (Op == BO_LT && Val == 0) return true;
      if (Op == BO_LE && Val == 1) return true;
    }
  }

  return false;
}

static bool containsGuardInAndChain(const Expr *E, const VarDecl *SepVD,
                                    const VarDecl *PtrVD, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (isGuardOnSep(E, SepVD, PtrVD, C))
    return true;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      return containsGuardInAndChain(BO->getLHS(), SepVD, PtrVD, C) ||
             containsGuardInAndChain(BO->getRHS(), SepVD, PtrVD, C);
    }
  }

  return false;
}

static bool findSepAssignment(const CompoundStmt *CS, const IfStmt *If,
                              const VarDecl *PtrVD, const VarDecl *&SepVD,
                              CheckerContext &C) {
  if (!CS || !If || !PtrVD)
    return false;

  for (const Stmt *S : CS->body()) {
    if (S == If)
      break;

    if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->getOpcode() == BO_Assign) {
        const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
        const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
        const VarDecl *LVD = getVarDeclFromExpr(LHS);
        if (!LVD)
          continue;

        int64_t Off = 0;
        if (matchPtrAccess(RHS, PtrVD, Off, C) && Off == 0) {
          SepVD = LVD;
          return true;
        }
      }
    }

    if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
      for (const Decl *D : DS->decls()) {
        const VarDecl *VD = dyn_cast<VarDecl>(D);
        if (!VD)
          continue;

        const Expr *Init = VD->getInit();
        if (!Init)
          continue;

        int64_t Off = 0;
        if (matchPtrAccess(Init, PtrVD, Off, C) && Off == 0) {
          SepVD = VD;
          return true;
        }
      }
    }
  }

  return false;
}

static bool checkAndChain(const Expr *E, const VarDecl *SepVD,
                          const VarDecl *PtrVD, bool SepChecked,
                          CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();

      bool Found = checkAndChain(LHS, SepVD, PtrVD, SepChecked, C);
      bool LHSGuards =
          SepChecked || containsGuardInAndChain(LHS, SepVD, PtrVD, C);

      Found = Found || checkAndChain(RHS, SepVD, PtrVD, LHSGuards, C);
      return Found;
    }
  }

  if (!SepChecked && containsDangerousAccess(E, PtrVD, C))
    return true;

  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read", "Memory safety")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  const IfStmt *If = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!If)
    return;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(If, C);
  if (!CS)
    return;

  const VarDecl *PtrVD = nullptr;
  int64_t Offset = 0;
  if (!findDangerousSubscript(Cond, PtrVD, Offset, C))
    return;
  if (!PtrVD)
    return;

  const VarDecl *SepVD = nullptr;
  if (!findSepAssignment(CS, If, PtrVD, SepVD, C))
    return;
  if (!SepVD)
    return;

  if (!checkAndChain(Cond, SepVD, PtrVD, false, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential out-of-bounds read: missing NUL check before fixed-offset access",
      N);
  report->addRange(Cond->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects fixed-offset string reads before checking for NUL termination",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
