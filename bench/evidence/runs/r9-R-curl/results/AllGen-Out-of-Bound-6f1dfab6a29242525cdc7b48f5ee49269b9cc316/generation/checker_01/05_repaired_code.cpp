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

#include <functional>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NUL check before fixed-offset lookahead",
                       "Logic Error")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  bool matchSubscriptEqualsVar(const Expr *E, const ValueDecl *&P,
                               const ValueDecl *&S, int64_t &Index,
                               ASTContext &ACtx) const;
  bool isTruthinessGuard(const Expr *E, const ValueDecl *S,
                         ASTContext &ACtx) const;
  bool isIncrementOf(const Stmt *S, const ValueDecl *P,
                     ASTContext &ACtx) const;
  bool isAssignFromSubscript(const Stmt *S, const ValueDecl *SVar,
                             const ValueDecl *P, ASTContext &ACtx) const;
  bool exprDerivesFromRole(const Expr *E, StringRef Role,
                           CheckerContext &C) const;
  const Expr *findNullOnFailureCall(const CompoundStmt *CS, const IfStmt *IS,
                                    const VarDecl *PVD,
                                    CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;
  CondE = CondE->IgnoreParenImpCasts();

  // Flatten && chain
  SmallVector<const Expr *, 8> Operands;
  std::function<void(const Expr *)> flatten = [&](const Expr *E) {
    E = E->IgnoreParenImpCasts();
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      if (BO->getOpcode() == BO_LAnd) {
        flatten(BO->getLHS());
        flatten(BO->getRHS());
        return;
      }
    }
    Operands.push_back(E);
  };
  flatten(CondE);

  ASTContext &ACtx = C.getASTContext();

  const ValueDecl *P = nullptr;
  const ValueDecl *S = nullptr;
  const Expr *FirstLookahead = nullptr;
  bool foundP2 = false;

  for (const Expr *Op : Operands) {
    const ValueDecl *CurP = nullptr;
    const ValueDecl *CurS = nullptr;
    int64_t Index = -1;
    if (matchSubscriptEqualsVar(Op, CurP, CurS, Index, ACtx)) {
      if (Index == 1 && !FirstLookahead) {
        P = CurP;
        S = CurS;
        FirstLookahead = Op;
      } else if (Index == 2 && P == CurP && S == CurS) {
        foundP2 = true;
      }
    }
  }

  if (!P || !S || !FirstLookahead || !foundP2)
    return;

  // Check if S is already guarded before FirstLookahead
  bool foundGuard = false;
  for (const Expr *Op : Operands) {
    if (Op == FirstLookahead)
      break;
    if (isTruthinessGuard(Op, S, ACtx)) {
      foundGuard = true;
      break;
    }
  }
  if (foundGuard)
    return;

  // Locate enclosing IfStmt and CompoundStmt
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
  if (!CS)
    return;

  // Check statements before the IfStmt
  int incrIdx = -1, assignIdx = -1;
  int idx = 0;
  for (const Stmt *BodyS : CS->body()) {
    if (BodyS == IS)
      break;
    if (incrIdx == -1 && isIncrementOf(BodyS, P, ACtx))
      incrIdx = idx;
    if (assignIdx == -1 && isAssignFromSubscript(BodyS, S, P, ACtx))
      assignIdx = idx;
    idx++;
  }
  if (incrIdx == -1 || assignIdx == -1 || incrIdx > assignIdx)
    return;

  // Check P's declaration / assignment from null_on_failure
  const auto *PVD = dyn_cast<VarDecl>(P);
  if (!PVD)
    return;

  const Expr *NullOnFailureCall = nullptr;
  if (PVD->hasInit()) {
    NullOnFailureCall = PVD->getInit();
  } else {
    NullOnFailureCall = findNullOnFailureCall(CS, IS, PVD, C);
  }
  if (!NullOnFailureCall)
    return;

  NullOnFailureCall = NullOnFailureCall->IgnoreParenImpCasts();
  const auto *CE = dyn_cast<CallExpr>(NullOnFailureCall);
  if (!CE)
    return;
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD || !knighter::declIsRole(FD, "null_on_failure"))
    return;

  if (CE->getNumArgs() > 0) {
    if (!exprDerivesFromRole(CE->getArg(0), "parser_input", C))
      return;
  } else {
    return;
  }

  // Report the bug
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing NUL check before fixed-offset lookahead", N);
  report->addRange(Condition->getSourceRange());
  C.emitReport(std::move(report));
}

bool SAGenTestChecker::matchSubscriptEqualsVar(const Expr *E,
                                               const ValueDecl *&P,
                                               const ValueDecl *&S,
                                               int64_t &Index,
                                               ASTContext &ACtx) const {
  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_EQ)
    return false;
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  auto tryMatch = [&](const Expr *SubE, const Expr *VarE) -> bool {
    SubE = SubE->IgnoreParenImpCasts();
    VarE = VarE->IgnoreParenImpCasts();
    const auto *ASE = dyn_cast<ArraySubscriptExpr>(SubE);
    if (!ASE)
      return false;
    const Expr *BaseE = ASE->getBase()->IgnoreParenImpCasts();
    const auto *DRE = dyn_cast<DeclRefExpr>(BaseE);
    if (!DRE)
      return false;
    const auto *VarDRE = dyn_cast<DeclRefExpr>(VarE);
    if (!VarDRE)
      return false;
    Expr::EvalResult Res;
    if (!ASE->getIdx()->EvaluateAsInt(Res, ACtx))
      return false;
    Index = Res.Val.getInt().getSExtValue();
    P = DRE->getDecl();
    S = VarDRE->getDecl();
    return true;
  };

  if (tryMatch(LHS, RHS))
    return true;
  if (tryMatch(RHS, LHS))
    return true;
  return false;
}

bool SAGenTestChecker::isTruthinessGuard(const Expr *E, const ValueDecl *S,
                                         ASTContext &ACtx) const {
  E = E->IgnoreParenImpCasts();
  // Case 1: just S
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == S;
  }
  // Case 2: S != 0 or 0 != S
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      auto isS = [&](const Expr *e) -> bool {
        if (const auto *DRE = dyn_cast<DeclRefExpr>(e))
          return DRE->getDecl() == S;
        return false;
      };
      auto isZero = [&](const Expr *e) -> bool {
        Expr::EvalResult Res;
        if (e->EvaluateAsInt(Res, ACtx)) {
          return Res.Val.getInt().getSExtValue() == 0;
        }
        return e->isNullPointerConstant(ACtx, Expr::NPC_ValueDependentIsNull);
      };
      if ((isS(LHS) && isZero(RHS)) || (isZero(LHS) && isS(RHS))) {
        return true;
      }
    }
  }
  return false;
}

bool SAGenTestChecker::isIncrementOf(const Stmt *S, const ValueDecl *P,
                                     ASTContext &ACtx) const {
  const Expr *E = dyn_cast<Expr>(S);
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  // Post-increment: P++
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        return DRE->getDecl() == P;
      }
    }
  }

  // Compound assignment: P += 1
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_AddAssign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (DRE->getDecl() == P) {
          Expr::EvalResult Res;
          if (BO->getRHS()->EvaluateAsInt(Res, ACtx)) {
            return Res.Val.getInt().getSExtValue() == 1;
          }
        }
      }
    }
  }

  // Simple assignment: P = P + 1
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (DRE->getDecl() == P) {
          const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
          if (const auto *Add = dyn_cast<BinaryOperator>(RHS)) {
            if (Add->getOpcode() == BO_Add) {
              const Expr *L = Add->getLHS()->IgnoreParenImpCasts();
              const Expr *R = Add->getRHS()->IgnoreParenImpCasts();
              auto isP = [&](const Expr *e) -> bool {
                if (const auto *DRE = dyn_cast<DeclRefExpr>(e))
                  return DRE->getDecl() == P;
                return false;
              };
              auto isOne = [&](const Expr *e) -> bool {
                Expr::EvalResult Res;
                if (e->EvaluateAsInt(Res, ACtx))
                  return Res.Val.getInt().getSExtValue() == 1;
                return false;
              };
              if ((isP(L) && isOne(R)) || (isOne(L) && isP(R))) {
                return true;
              }
            }
          }
        }
      }
    }
  }

  return false;
}

bool SAGenTestChecker::isAssignFromSubscript(const Stmt *S,
                                             const ValueDecl *SVar,
                                             const ValueDecl *P,
                                             ASTContext &ACtx) const {
  const Expr *E = dyn_cast<Expr>(S);
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Assign)
    return false;
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const auto *LHSDRE = dyn_cast<DeclRefExpr>(LHS);
  if (!LHSDRE || LHSDRE->getDecl() != SVar)
    return false;
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  // P[0]
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(RHS)) {
    const Expr *BaseE = ASE->getBase()->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(BaseE)) {
      if (DRE->getDecl() == P) {
        Expr::EvalResult Res;
        if (ASE->getIdx()->EvaluateAsInt(Res, ACtx)) {
          return Res.Val.getInt().getSExtValue() == 0;
        }
      }
    }
  }

  // *P
  if (const auto *UO = dyn_cast<UnaryOperator>(RHS)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        return DRE->getDecl() == P;
      }
    }
  }

  return false;
}

bool SAGenTestChecker::exprDerivesFromRole(const Expr *E, StringRef Role,
                                           CheckerContext &C) const {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (FD && knighter::declIsRole(FD, Role)) {
      return true;
    }
  }

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (VD && VD->hasInit()) {
      return exprDerivesFromRole(VD->getInit(), Role, C);
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    return exprDerivesFromRole(BO->getLHS(), Role, C) ||
           exprDerivesFromRole(BO->getRHS(), Role, C);
  }

  return false;
}

const Expr *SAGenTestChecker::findNullOnFailureCall(const CompoundStmt *CS,
                                                    const IfStmt *IS,
                                                    const VarDecl *PVD,
                                                    CheckerContext &C) const {
  for (const Stmt *S : CS->body()) {
    if (S == IS)
      break;
    const Expr *E = dyn_cast<Expr>(S);
    if (!E)
      continue;
    E = E->IgnoreParenImpCasts();
    const auto *BO = dyn_cast<BinaryOperator>(E);
    if (!BO || BO->getOpcode() != BO_Assign)
      continue;
    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const auto *DRE = dyn_cast<DeclRefExpr>(LHS);
    if (!DRE || DRE->getDecl() != PVD)
      continue;
    const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
    const auto *CE = dyn_cast<CallExpr>(RHS);
    if (!CE)
      continue;
    const FunctionDecl *FD = CE->getDirectCallee();
    if (FD && knighter::declIsRole(FD, "null_on_failure")) {
      return CE;
    }
  }
  return nullptr;
}

//===----------------------------------------------------------------------===//
// Checker Registration
//===----------------------------------------------------------------------===//

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NUL check before fixed-offset lookahead",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["curlx_dyn_ptr"], "description": "returns a pointer to the input buffer being parsed"},
  "null_on_failure": {"names": ["strchr"], "description": "returns NULL if the searched character is not found"}
}
*/
