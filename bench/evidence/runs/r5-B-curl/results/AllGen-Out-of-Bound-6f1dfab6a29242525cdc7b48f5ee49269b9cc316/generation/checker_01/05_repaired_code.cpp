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
#include "clang/Basic/SourceManager.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

struct UnsafeAccess {
  const VarDecl *Ptr;
  int64_t Index;
  const ArraySubscriptExpr *ASE;
};

struct PointerState {
  bool HasStrchr = false;
  bool HasIncrement = false;
  const VarDecl *Sep = nullptr;
  SourceLocation StrchrLoc;
  SourceLocation IncLoc;
};

static bool isDelimiterSearchCall(const CallExpr *CE, CheckerContext &C) {
  if (!CE)
    return false;
  const FunctionDecl *FD = CE->getDirectCallee();
  if (FD) {
    StringRef Name = FD->getName();
    if (Name == "strchr" || Name == "strrchr" || Name == "memchr")
      return true;
  }
  const Expr *Callee = CE->getCallee();
  if (!Callee)
    return false;
  return ExprHasName(Callee, "strchr", C) ||
         ExprHasName(Callee, "strrchr", C) ||
         ExprHasName(Callee, "memchr", C);
}

static const VarDecl *getVarDeclFromExpr(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E))
    return dyn_cast<VarDecl>(DRE->getDecl());
  return nullptr;
}

static bool isArraySubscriptOfVar(const Expr *E, const VarDecl *VD, int64_t Index,
                                  CheckerContext &C) {
  if (!E)
    return false;
  const ArraySubscriptExpr *ASE =
      dyn_cast<ArraySubscriptExpr>(E->IgnoreParenImpCasts());
  if (!ASE)
    return false;
  const VarDecl *BaseVD = getVarDeclFromExpr(ASE->getLHS());
  if (BaseVD != VD)
    return false;
  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, ASE->getRHS(), C))
    return false;
  return EvalRes.getSExtValue() == Index;
}

static bool isNonNullGuard(const Expr *E, const VarDecl *Ptr,
                           const VarDecl *Sep, CheckerContext &C) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  // Case 1: E is just `S` or `P[0]` in boolean context.
  if (Sep && getVarDeclFromExpr(E) == Sep)
    return true;
  if (isArraySubscriptOfVar(E, Ptr, 0, C))
    return true;

  // Case 2: E is `S != 0` or `P[0] != 0`.
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      auto isZero = [&](const Expr *Z) -> bool {
        llvm::APSInt Val;
        return EvaluateExprToInt(Val, Z, C) && Val.isZero();
      };
      if (isZero(RHS)) {
        if (Sep && getVarDeclFromExpr(LHS) == Sep)
          return true;
        if (isArraySubscriptOfVar(LHS, Ptr, 0, C))
          return true;
      }
      if (isZero(LHS)) {
        if (Sep && getVarDeclFromExpr(RHS) == Sep)
          return true;
        if (isArraySubscriptOfVar(RHS, Ptr, 0, C))
          return true;
      }
    }
  }
  return false;
}

static void collectUnsafeAccesses(const Stmt *S,
                                  llvm::SmallVectorImpl<UnsafeAccess> &Out,
                                  CheckerContext &C) {
  if (!S)
    return;
  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(S)) {
    const Expr *Base = ASE->getLHS()->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base)) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (VD->getType()->isPointerType()) {
          llvm::APSInt EvalRes;
          if (EvaluateExprToInt(EvalRes, ASE->getRHS(), C)) {
            int64_t Idx = EvalRes.getSExtValue();
            if (Idx > 0) {
              Out.push_back({VD, Idx, ASE});
            }
          }
        }
      }
    }
  }
  for (const Stmt *Child : S->children()) {
    collectUnsafeAccesses(Child, Out, C);
  }
}

static void findPriorInfo(const Stmt *S, const VarDecl *P, SourceLocation IfLoc,
                          CheckerContext &C, PointerState &Info) {
  if (!S)
    return;
  const SourceManager &SM = C.getSourceManager();
  SourceLocation SLoc = S->getBeginLoc();
  if (SLoc.isValid() && !SM.isBeforeInTranslationUnit(SLoc, IfLoc)) {
    return;
  }

  if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(D)) {
        if (const Expr *Init = VD->getInit()) {
          if (VD == P) {
            if (const CallExpr *CE =
                    dyn_cast<CallExpr>(Init->IgnoreParenImpCasts())) {
              if (isDelimiterSearchCall(CE, C)) {
                Info.HasStrchr = true;
                Info.StrchrLoc = Init->getBeginLoc();
              }
            }
          } else {
            if (isArraySubscriptOfVar(Init, P, 0, C)) {
              Info.Sep = VD;
            }
          }
        }
      }
    }
  }

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      const VarDecl *LHSPtr = getVarDeclFromExpr(LHS);
      if (LHSPtr == P) {
        if (const CallExpr *CE = dyn_cast<CallExpr>(RHS)) {
          if (isDelimiterSearchCall(CE, C)) {
            Info.HasStrchr = true;
            Info.StrchrLoc = BO->getBeginLoc();
          }
        }
        if (const BinaryOperator *Add = dyn_cast<BinaryOperator>(RHS)) {
          if (Add->getOpcode() == BO_Add) {
            const VarDecl *AddL = getVarDeclFromExpr(Add->getLHS());
            const VarDecl *AddR = getVarDeclFromExpr(Add->getRHS());
            llvm::APSInt Val;
            if (AddL == P && EvaluateExprToInt(Val, Add->getRHS(), C) &&
                Val.getSExtValue() == 1) {
              Info.HasIncrement = true;
              Info.IncLoc = BO->getBeginLoc();
            } else if (AddR == P && EvaluateExprToInt(Val, Add->getLHS(), C) &&
                       Val.getSExtValue() == 1) {
              Info.HasIncrement = true;
              Info.IncLoc = BO->getBeginLoc();
            }
          }
        }
      } else if (LHSPtr) {
        if (isArraySubscriptOfVar(RHS, P, 0, C)) {
          Info.Sep = LHSPtr;
        }
      }
    }
  }

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->isIncrementDecrementOp()) {
      const VarDecl *VD = getVarDeclFromExpr(UO->getSubExpr());
      if (VD == P) {
        if (UO->getOpcode() == UO_PreInc || UO->getOpcode() == UO_PostInc) {
          Info.HasIncrement = true;
          Info.IncLoc = UO->getBeginLoc();
        }
      }
    }
  }

  if (const CompoundAssignOperator *CAO = dyn_cast<CompoundAssignOperator>(S)) {
    if (CAO->getOpcode() == BO_AddAssign) {
      const VarDecl *VD = getVarDeclFromExpr(CAO->getLHS());
      if (VD == P) {
        llvm::APSInt Val;
        if (EvaluateExprToInt(Val, CAO->getRHS(), C) &&
            Val.getSExtValue() == 1) {
          Info.HasIncrement = true;
          Info.IncLoc = CAO->getBeginLoc();
        }
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    findPriorInfo(Child, P, IfLoc, C, Info);
  }
}

static void flattenAnd(const Expr *E, llvm::SmallVectorImpl<const Expr *> &Out) {
  if (!E)
    return;
  E = E->IgnoreParens();
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      flattenAnd(BO->getLHS(), Out);
      flattenAnd(BO->getRHS(), Out);
      return;
    }
  }
  Out.push_back(E);
}

static bool containsStmt(const Stmt *Parent, const Stmt *Child) {
  if (!Parent || !Child)
    return false;
  if (Parent == Child)
    return true;
  for (const Stmt *S : Parent->children()) {
    if (containsStmt(S, Child))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read after delimiter",
                       "Memory Safety")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportBug(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
};

void SAGenTestChecker::reportBug(const ArraySubscriptExpr *ASE,
                                 CheckerContext &C) const {
  if (!ASE)
    return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Out-of-bounds read after strchr delimiter", N);
  Report->addRange(ASE->getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *If = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!If || If->getCond() != Condition)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  llvm::SmallVector<UnsafeAccess, 8> Accesses;
  collectUnsafeAccesses(CondE, Accesses, C);
  if (Accesses.empty())
    return;

  llvm::DenseMap<const VarDecl *, llvm::SmallVector<UnsafeAccess, 4>> ByPtr;
  for (const auto &UA : Accesses)
    ByPtr[UA.Ptr].push_back(UA);

  SourceLocation IfLoc = If->getBeginLoc();
  const FunctionDecl *FD =
      dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  llvm::SmallVector<const Expr *, 8> Operands;
  flattenAnd(CondE, Operands);

  for (auto &Entry : ByPtr) {
    const VarDecl *P = Entry.first;
    PointerState Info;
    findPriorInfo(Body, P, IfLoc, C, Info);
    if (!Info.HasStrchr || !Info.HasIncrement)
      continue;

    bool Guarded = false;
    for (const Expr *Op : Operands) {
      if (isNonNullGuard(Op, P, Info.Sep, C)) {
        Guarded = true;
        continue;
      }
      bool ContainsUnsafe = false;
      const ArraySubscriptExpr *Offending = nullptr;
      for (const auto &UA : Entry.second) {
        if (containsStmt(Op, UA.ASE)) {
          ContainsUnsafe = true;
          Offending = UA.ASE;
          break;
        }
      }
      if (ContainsUnsafe && !Guarded) {
        reportBug(Offending, C);
        break;
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects out-of-bounds read after strchr delimiter without prior NUL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
