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

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

//===----------------------------------------------------------------------===//
// AST helpers
//===----------------------------------------------------------------------===//

static const VarDecl *getPointerVarFromExpr(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<VarDecl>(DRE->getDecl());
  }
  return nullptr;
}

static bool evalToInt64(const Expr *E, CheckerContext &C, int64_t &Val) {
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, E, C)) {
    Val = EvalRes.getSExtValue();
    return true;
  }
  return false;
}

static bool isConstantIntGE1(const Expr *E, CheckerContext &C) {
  int64_t Val;
  return evalToInt64(E, C, Val) && Val >= 1;
}

static bool isConstantIntZero(const Expr *E, CheckerContext &C) {
  int64_t Val;
  return evalToInt64(E, C, Val) && Val == 0;
}

static bool isZeroConstant(const Expr *E, CheckerContext &C) {
  return isConstantIntZero(E, C);
}

// Check if E is P[0] or *P
static bool isPtr0Read(const Expr *E, const VarDecl *PtrVar, CheckerContext &C) {
  if (!E || !PtrVar)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    if (isConstantIntZero(ASE->getIdx(), C)) {
      const VarDecl *VD = getPointerVarFromExpr(ASE->getBase());
      return VD == PtrVar;
    }
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      const VarDecl *VD = getPointerVarFromExpr(UO->getSubExpr());
      return VD == PtrVar;
    }
  }
  return false;
}

// Find first lookahead read P[N] with N >= 1 in E.
// Returns the expression and sets BaseVar.
static const Expr *findLookaheadRead(const Expr *E, CheckerContext &C,
                                     const VarDecl *&BaseVar) {
  if (!E)
    return nullptr;
  E = E->IgnoreParens();

  // Array subscript P[N]
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    if (isConstantIntGE1(ASE->getIdx(), C)) {
      const VarDecl *VD = getPointerVarFromExpr(ASE->getBase());
      if (VD) {
        BaseVar = VD;
        return ASE;
      }
    }
  }

  // Dereference of P + N
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParens();
      if (const auto *BO = dyn_cast<BinaryOperator>(Sub)) {
        if (BO->getOpcode() == BO_Add) {
          const Expr *L = BO->getLHS();
          const Expr *R = BO->getRHS();
          if (isConstantIntGE1(R, C)) {
            const VarDecl *VD = getPointerVarFromExpr(L);
            if (VD) {
              BaseVar = VD;
              return E;
            }
          }
          if (isConstantIntGE1(L, C)) {
            const VarDecl *VD = getPointerVarFromExpr(R);
            if (VD) {
              BaseVar = VD;
              return E;
            }
          }
        }
      }
    }
  }

  // Recurse into children in evaluation order.
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (const Expr *Res = findLookaheadRead(BO->getLHS(), C, BaseVar))
      return Res;
    return findLookaheadRead(BO->getRHS(), C, BaseVar);
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    return findLookaheadRead(UO->getSubExpr(), C, BaseVar);
  }
  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    for (const Expr *Arg : CE->arguments()) {
      if (const Expr *Res = findLookaheadRead(Arg, C, BaseVar))
        return Res;
    }
    return nullptr;
  }
  if (const auto *PE = dyn_cast<ParenExpr>(E)) {
    return findLookaheadRead(PE->getSubExpr(), C, BaseVar);
  }
  if (const auto *ICE = dyn_cast<ImplicitCastExpr>(E)) {
    return findLookaheadRead(ICE->getSubExpr(), C, BaseVar);
  }
  if (const auto *CE = dyn_cast<CastExpr>(E)) {
    return findLookaheadRead(CE->getSubExpr(), C, BaseVar);
  }

  return nullptr;
}

static bool isNullOnFailureCall(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *CE = dyn_cast<CallExpr>(E)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      return knighter::declIsRole(FD, "null_on_failure");
    }
  }
  return false;
}

static bool isIncrementOfVar(const Stmt *S, const VarDecl *VD,
                             CheckerContext &C) {
  if (!S || !VD)
    return false;

  if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        return DRE->getDecl() == VD;
      }
    }
  }

  if (const auto *BO = dyn_cast<CompoundAssignOperator>(S)) {
    if (BO->getOpcode() == BO_AddAssign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (DRE->getDecl() == VD) {
          int64_t Val;
          if (evalToInt64(BO->getRHS()->IgnoreParenImpCasts(), C, Val) &&
              Val == 1)
            return true;
        }
      }
    }
  }

  return false;
}

static const VarDecl *getAssignmentToPtr0(const Stmt *S, const VarDecl *PtrVar,
                                          CheckerContext &C) {
  if (!S || !PtrVar)
    return nullptr;

  // Handle `S = P[0];`
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (const VarDecl *SVar = dyn_cast<VarDecl>(DRE->getDecl())) {
          if (isPtr0Read(RHS, PtrVar, C))
            return SVar;
        }
      }
    }
  }

  // Handle `char S = P[0];` in DeclStmt
  if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      if (const auto *VD = dyn_cast<VarDecl>(D)) {
        if (const Expr *Init = VD->getInit()) {
          if (isPtr0Read(Init->IgnoreParenImpCasts(), PtrVar, C))
            return VD;
        }
      }
    }
  }

  return nullptr;
}

static void flattenAnd(const Expr *E, llvm::SmallVectorImpl<const Expr *> &Ops) {
  if (!E)
    return;
  E = E->IgnoreParens();
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      flattenAnd(BO->getLHS(), Ops);
      flattenAnd(BO->getRHS(), Ops);
      return;
    }
  }
  Ops.push_back(E);
}

static bool containsExpr(const Stmt *Root, const Stmt *Target) {
  if (!Root || !Target)
    return false;
  if (Root == Target)
    return true;
  for (const Stmt *Child : Root->children()) {
    if (Child && containsExpr(Child, Target))
      return true;
  }
  return false;
}

static bool isSVarExpr(const Expr *E, const VarDecl *VD) {
  if (!E || !VD)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == VD;
  }
  return false;
}

static bool isNonZeroCheckOnVar(const Expr *E, const VarDecl *VD,
                                CheckerContext &C) {
  if (!E || !VD)
    return false;
  E = E->IgnoreParens();

  // Direct use: if (sep)
  if (isSVarExpr(E, VD))
    return true;

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->isComparisonOp() && BO->getOpcode() == BO_NE) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      if (isSVarExpr(L, VD) && isZeroConstant(R, C))
        return true;
      if (isSVarExpr(R, VD) && isZeroConstant(L, C))
        return true;
      if (isZeroConstant(L, C) && isSVarExpr(R, VD))
        return true;
      if (isZeroConstant(R, C) && isSVarExpr(L, VD))
        return true;
    }
  }
  return false;
}

static bool isNonZeroCheckOnP0(const Expr *E, const VarDecl *PtrVar,
                               CheckerContext &C) {
  if (!E || !PtrVar)
    return false;
  E = E->IgnoreParens();

  if (isPtr0Read(E, PtrVar, C))
    return true;

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->isComparisonOp() && BO->getOpcode() == BO_NE) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      if (isPtr0Read(L, PtrVar, C) && isZeroConstant(R, C))
        return true;
      if (isPtr0Read(R, PtrVar, C) && isZeroConstant(L, C))
        return true;
    }
  }
  return false;
}

//===----------------------------------------------------------------------===//
// Checker class
//===----------------------------------------------------------------------===//

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read", "Memory safety")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const VarDecl *PtrVar = nullptr;
  const Expr *Lookahead = findLookaheadRead(CondE, C, PtrVar);
  if (!Lookahead || !PtrVar)
    return;

  // Verify PtrVar is initialized from a null-on-failure function.
  if (!isNullOnFailureCall(PtrVar->getInit()))
    return;

  // Find the enclosing IfStmt and the nearest CompoundStmt.
  const IfStmt *If = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!If)
    return;
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(Condition, C);
  if (!CS)
    return;

  // Locate the IfStmt inside the compound.
  int IfIdx = -1;
  for (size_t i = 0; i < CS->size(); ++i) {
    if (CS->body_begin()[i] == If) {
      IfIdx = i;
      break;
    }
  }
  if (IfIdx < 0)
    return;

  // Scan preceding statements for `PtrVar++` and `S = PtrVar[0]`.
  int IncIdx = -1;
  int SAssignIdx = -1;
  const VarDecl *SVar = nullptr;

  for (int i = IfIdx - 1; i >= 0; --i) {
    const Stmt *S = CS->body_begin()[i];
    if (IncIdx == -1 && isIncrementOfVar(S, PtrVar, C)) {
      IncIdx = i;
      continue;
    }
    if (SAssignIdx == -1) {
      if (const VarDecl *VD = getAssignmentToPtr0(S, PtrVar, C)) {
        SAssignIdx = i;
        SVar = VD;
        continue;
      }
    }
  }

  if (IncIdx == -1 || SAssignIdx == -1 || !(IncIdx < SAssignIdx))
    return;
  if (!SVar)
    return;

  // Flatten the top-level && chain of the condition.
  llvm::SmallVector<const Expr *, 8> Ops;
  flattenAnd(CondE, Ops);

  // Find the operand containing the lookahead read.
  int LookaheadOpIdx = -1;
  for (size_t i = 0; i < Ops.size(); ++i) {
    if (containsExpr(Ops[i], Lookahead)) {
      LookaheadOpIdx = i;
      break;
    }
  }
  if (LookaheadOpIdx < 0)
    return;

  // Check whether any earlier operand guards the current byte.
  bool Guarded = false;
  for (int i = 0; i < LookaheadOpIdx; ++i) {
    const Expr *Op = Ops[i];
    if (isNonZeroCheckOnVar(Op, SVar, C) ||
        isNonZeroCheckOnP0(Op, PtrVar, C)) {
      Guarded = true;
      break;
    }
  }

  if (Guarded)
    return;

  // Report the bug.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Possible out-of-bounds read: lookahead past NUL terminator without "
      "checking current byte",
      N);
  Report->addRange(Lookahead->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects lookahead reads past NUL terminator without checking current byte",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "null_on_failure": {"names": ["strchr"], "description": "returns NULL if the search fails; the returned pointer is valid only when non-NULL and points into the searched buffer"},
  "parser_input": {"names": ["curlx_dyn_ptr"], "description": "returns a NUL-terminated pointer to a buffer being parsed"},
  "error_setter": {"names": ["failf"], "description": "printf-style function that records an error message"}
}
*/
