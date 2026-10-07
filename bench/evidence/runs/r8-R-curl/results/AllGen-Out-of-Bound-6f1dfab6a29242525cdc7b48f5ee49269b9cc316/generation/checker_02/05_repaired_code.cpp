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
#include "knighter/roles.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

bool isZeroLiteral(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue() == 0;
  if (const CharacterLiteral *CL = dyn_cast<CharacterLiteral>(E))
    return CL->getValue() == 0;
  return false;
}

bool matchPtrSubscript(const Expr *E, const VarDecl *PtrVD, int &Index) {
  if (!E || !PtrVD)
    return false;
  E = E->IgnoreParenImpCasts();

  auto matchDecl = [&](const Expr *Base) -> bool {
    Base = Base->IgnoreParenImpCasts();
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base);
    return DRE && DRE->getDecl() == PtrVD;
  };

  auto getInt = [](const Expr *E, int &Val) -> bool {
    E = E->IgnoreParenImpCasts();
    if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
      Val = IL->getValue().getSExtValue();
      return true;
    }
    return false;
  };

  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    if (matchDecl(ASE->getBase()))
      return getInt(ASE->getIdx(), Index);
  }

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Sub)) {
        if (BO->getOpcode() == BO_Add) {
          const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
          const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
          if (matchDecl(L))
            return getInt(R, Index);
          if (matchDecl(R))
            return getInt(L, Index);
        }
      }
    }
  }
  return false;
}

const Expr *findFirstLookahead(const Stmt *S, const VarDecl *&PtrVD, int &Index) {
  if (!S)
    return nullptr;

  if (const Expr *E = dyn_cast<Expr>(S)) {
    E = E->IgnoreParenImpCasts();

    if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(
              ASE->getBase()->IgnoreParenImpCasts())) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(
                  ASE->getIdx()->IgnoreParenImpCasts())) {
            int idx = IL->getValue().getSExtValue();
            if (idx >= 1) {
              PtrVD = VD;
              Index = idx;
              return E;
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
            const DeclRefExpr *DRE = nullptr;
            const IntegerLiteral *IL = nullptr;
            if ((DRE = dyn_cast<DeclRefExpr>(L)) &&
                (IL = dyn_cast<IntegerLiteral>(R))) {
              if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
                int idx = IL->getValue().getSExtValue();
                if (idx >= 1) {
                  PtrVD = VD;
                  Index = idx;
                  return E;
                }
              }
            } else if ((DRE = dyn_cast<DeclRefExpr>(R)) &&
                       (IL = dyn_cast<IntegerLiteral>(L))) {
              if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
                int idx = IL->getValue().getSExtValue();
                if (idx >= 1) {
                  PtrVD = VD;
                  Index = idx;
                  return E;
                }
              }
            }
          }
        }
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (const Expr *Res = findFirstLookahead(Child, PtrVD, Index))
      return Res;
  }
  return nullptr;
}

bool isPtrAdvance(const Stmt *S, const VarDecl *PtrVD) {
  if (!S || !PtrVD)
    return false;

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_PreInc || UO->getOpcode() == UO_PostInc) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub))
        return DRE->getDecl() == PtrVD;
    }
  }

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_AddAssign) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(L)) {
        if (DRE->getDecl() == PtrVD) {
          if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(R))
            return IL->getValue().getSExtValue() == 1;
        }
      }
    }

    if (BO->getOpcode() == BO_Assign) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(L)) {
        if (DRE->getDecl() == PtrVD) {
          if (const BinaryOperator *Add = dyn_cast<BinaryOperator>(R)) {
            if (Add->getOpcode() == BO_Add) {
              const Expr *A = Add->getLHS()->IgnoreParenImpCasts();
              const Expr *B = Add->getRHS()->IgnoreParenImpCasts();
              const DeclRefExpr *PtrDRE = nullptr;
              const IntegerLiteral *IL = nullptr;
              if ((PtrDRE = dyn_cast<DeclRefExpr>(A)) &&
                  (IL = dyn_cast<IntegerLiteral>(B))) {
                return PtrDRE->getDecl() == PtrVD &&
                       IL->getValue().getSExtValue() == 1;
              } else if ((PtrDRE = dyn_cast<DeclRefExpr>(B)) &&
                         (IL = dyn_cast<IntegerLiteral>(A))) {
                return PtrDRE->getDecl() == PtrVD &&
                       IL->getValue().getSExtValue() == 1;
              }
            }
          }
        }
      }
    }
  }
  return false;
}

bool isSepAssignFromPtr0(const Stmt *S, const VarDecl *PtrVD,
                         const VarDecl *&SepVD) {
  if (!S || !PtrVD)
    return false;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(L)) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          int idx = -1;
          if (matchPtrSubscript(R, PtrVD, idx) && idx == 0) {
            SepVD = VD;
            return true;
          }
        }
      }
    }
  }

  if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(D)) {
        if (const Expr *Init = VD->getInit()) {
          int idx = -1;
          if (matchPtrSubscript(Init, PtrVD, idx) && idx == 0) {
            SepVD = VD;
            return true;
          }
        }
      }
    }
  }
  return false;
}

bool isDelimiterFinderCall(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  const CallExpr *CE = dyn_cast<CallExpr>(E);
  if (!CE)
    return false;

  if (const FunctionDecl *FD = CE->getDirectCallee())
    return knighter::isRole("delimiter_finder", FD->getName());

  if (const Expr *Callee = CE->getCallee()) {
    Callee = Callee->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Callee)) {
      if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(DRE->getDecl()))
        return knighter::isRole("delimiter_finder", FD->getName());
    }
  }
  return false;
}

bool ptrFromDelimiterFinder(const VarDecl *PtrVD, const CompoundStmt *CS,
                            const IfStmt *IS) {
  if (!PtrVD)
    return false;

  if (const Expr *Init = PtrVD->getInit()) {
    if (isDelimiterFinderCall(Init))
      return true;
  }

  if (!CS || !IS)
    return false;

  for (const Stmt *S : CS->body()) {
    if (S == IS)
      break;

    if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->getOpcode() == BO_Assign) {
        const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
        const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
        if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(L)) {
          if (DRE->getDecl() == PtrVD && isDelimiterFinderCall(R))
            return true;
        }
      }
    }
  }
  return false;
}

bool exprReferencesVar(const Stmt *S, const VarDecl *VD) {
  if (!S || !VD)
    return false;

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (DRE->getDecl() == VD)
      return true;
  }

  for (const Stmt *Child : S->children()) {
    if (exprReferencesVar(Child, VD))
      return true;
  }
  return false;
}

void flattenAnd(const Expr *E, llvm::SmallVectorImpl<const Expr *> &Ops) {
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

bool containsStmt(const Stmt *Root, const Stmt *Target) {
  if (!Root || !Target)
    return false;
  if (Root == Target)
    return true;
  for (const Stmt *Child : Root->children()) {
    if (containsStmt(Child, Target))
      return true;
  }
  return false;
}

bool isNonEmptyGuard(const Expr *E, const VarDecl *SepVD,
                     const VarDecl *PtrVD) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  auto isSep = [&](const Expr *X) -> bool {
    X = X->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(X))
      return DRE->getDecl() == SepVD;
    return false;
  };

  auto isPtr0 = [&](const Expr *X) -> bool {
    int idx = -1;
    return matchPtrSubscript(X, PtrVD, idx) && idx == 0;
  };

  if (isSep(E) || isPtr0(E))
    return true;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_NE) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      if (isZeroLiteral(R)) {
        if (isSep(L) || isPtr0(L))
          return true;
      }
      if (isZeroLiteral(L)) {
        if (isSep(R) || isPtr0(R))
          return true;
      }
    }
  }
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
  if (!Condition)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const VarDecl *PtrVD = nullptr;
  const Expr *Lookahead = nullptr;
  int LookaheadIndex = 0;
  Lookahead = findFirstLookahead(CondE, PtrVD, LookaheadIndex);
  if (!Lookahead || !PtrVD)
    return;

  const CompoundStmt *CS =
      findSpecificTypeInParents<CompoundStmt>(Condition, C);
  if (!CS)
    return;

  bool FoundIf = false;
  for (const Stmt *S : CS->body()) {
    if (S == IS) {
      FoundIf = true;
      break;
    }
  }
  if (!FoundIf)
    return;

  bool SawAdvance = false;
  bool SawSepAssign = false;
  const VarDecl *SepVD = nullptr;

  for (const Stmt *S : CS->body()) {
    if (S == IS)
      break;

    if (!SawAdvance && isPtrAdvance(S, PtrVD))
      SawAdvance = true;

    if (SawAdvance && !SawSepAssign &&
        isSepAssignFromPtr0(S, PtrVD, SepVD))
      SawSepAssign = true;
  }

  if (!SawAdvance || !SawSepAssign || !SepVD)
    return;

  if (!ptrFromDelimiterFinder(PtrVD, CS, IS))
    return;

  if (!exprReferencesVar(CondE, SepVD))
    return;

  llvm::SmallVector<const Expr *, 8> Ops;
  flattenAnd(CondE, Ops);
  if (Ops.empty())
    return;

  int LookaheadOpIdx = -1;
  for (unsigned I = 0; I < Ops.size(); ++I) {
    if (containsStmt(Ops[I], Lookahead)) {
      LookaheadOpIdx = (int)I;
      break;
    }
  }
  if (LookaheadOpIdx < 0)
    return;

  for (int I = 0; I < LookaheadOpIdx; ++I) {
    if (isNonEmptyGuard(Ops[I], SepVD, PtrVD))
      return; // safe
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential out-of-bounds read: missing non-empty check before "
      "fixed-offset lookahead",
      N);
  Report->addRange(Lookahead->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing non-empty check before fixed-offset lookahead reads",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "delimiter_finder": {
    "names": ["strchr"],
    "description": "function returning a pointer to the first occurrence of a delimiter character in a string, or null if not found"
  }
}
*/
