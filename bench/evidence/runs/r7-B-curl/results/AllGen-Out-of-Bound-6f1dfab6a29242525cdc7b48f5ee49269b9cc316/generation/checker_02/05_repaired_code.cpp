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
      : BT(new BugType(this, "Out-of-bounds read", "Memory access")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportBug(CheckerContext &C) const;
};

} // end anonymous namespace

// Helper: collect operands of && in left-to-right order.
static void collectAndOperands(const Expr *E,
                               llvm::SmallVectorImpl<const Expr *> &Ops) {
  if (!E)
    return;
  E = E->IgnoreParens();
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      collectAndOperands(BO->getLHS(), Ops);
      collectAndOperands(BO->getRHS(), Ops);
      return;
    }
  }
  Ops.push_back(E);
}

// Helper: check if expression contains a read ptr[1], ptr[2], or ptr[3].
static bool hasUnsafeRead(const Stmt *S, const VarDecl *PtrDecl,
                          CheckerContext &C) {
  if (!S)
    return false;

  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(S)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      if (DRE->getDecl() == PtrDecl) {
        llvm::APSInt IdxVal;
        if (EvaluateExprToInt(IdxVal, ASE->getIdx(), C)) {
          int64_t Idx = IdxVal.getSExtValue();
          if (Idx == 1 || Idx == 2 || Idx == 3)
            return true;
        }
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (hasUnsafeRead(Child, PtrDecl, C))
      return true;
  }
  return false;
}

void SAGenTestChecker::reportBug(CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Out-of-bounds read: delimiter may be NUL", N);
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  // Find enclosing IfStmt.
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;
  if (IS->getCond() != CondE)
    return;

  // Find the CompoundStmt containing this IfStmt.
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
  if (!CS)
    return;

  // Locate this IfStmt and take the immediately preceding statement.
  const Stmt *Prev = nullptr;
  bool Found = false;
  for (const Stmt *S : CS->body()) {
    if (S == IS) {
      Found = true;
      break;
    }
    Prev = S;
  }
  if (!Found || !Prev)
    return;

  // Check that the preceding statement is `sep = ptr[0]` or `sep = *ptr`.
  const Expr *PrevE = dyn_cast<Expr>(Prev);
  if (!PrevE)
    return;
  PrevE = PrevE->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(PrevE);
  if (!BO || BO->getOpcode() != BO_Assign)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const auto *LHSDRE = dyn_cast<DeclRefExpr>(LHS);
  if (!LHSDRE)
    return;
  const auto *SepDecl = dyn_cast<VarDecl>(LHSDRE->getDecl());
  if (!SepDecl)
    return;

  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  const VarDecl *PtrDecl = nullptr;

  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(RHS)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    const auto *BaseDRE = dyn_cast<DeclRefExpr>(Base);
    if (!BaseDRE)
      return;
    PtrDecl = dyn_cast<VarDecl>(BaseDRE->getDecl());
    if (!PtrDecl)
      return;

    llvm::APSInt IdxVal;
    if (!EvaluateExprToInt(IdxVal, ASE->getIdx(), C))
      return;
    if (!IdxVal.isZero())
      return;
  } else if (const auto *UO = dyn_cast<UnaryOperator>(RHS)) {
    if (UO->getOpcode() != UO_Deref)
      return;
    const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
    const auto *SubDRE = dyn_cast<DeclRefExpr>(Sub);
    if (!SubDRE)
      return;
    PtrDecl = dyn_cast<VarDecl>(SubDRE->getDecl());
    if (!PtrDecl)
      return;
  } else {
    return;
  }

  // Condition must be a `&&` chain.
  CondE = CondE->IgnoreParens();
  const auto *TopBO = dyn_cast<BinaryOperator>(CondE);
  if (!TopBO || TopBO->getOpcode() != BO_LAnd)
    return;

  // Flatten the && chain.
  llvm::SmallVector<const Expr *, 8> Ops;
  collectAndOperands(CondE, Ops);

  bool SepChecked = false;
  for (const Expr *Op : Ops) {
    const Expr *OpE = Op->IgnoreParenImpCasts();

    // Detect a guard on `sep`: `sep` or `sep != 0`.
    if (const auto *DRE = dyn_cast<DeclRefExpr>(OpE)) {
      if (DRE->getDecl() == SepDecl) {
        SepChecked = true;
        continue;
      }
    }

    if (const auto *BOp = dyn_cast<BinaryOperator>(OpE)) {
      if (BOp->getOpcode() == BO_NE) {
        const Expr *L = BOp->getLHS()->IgnoreParenImpCasts();
        const Expr *R = BOp->getRHS()->IgnoreParenImpCasts();

        auto IsSep = [&](const Expr *E) -> bool {
          if (const auto *D = dyn_cast<DeclRefExpr>(E))
            return D->getDecl() == SepDecl;
          return false;
        };
        auto IsZero = [&](const Expr *E) -> bool {
          llvm::APSInt Val;
          return EvaluateExprToInt(Val, E, C) && Val.isZero();
        };

        if ((IsSep(L) && IsZero(R)) || (IsSep(R) && IsZero(L))) {
          SepChecked = true;
          continue;
        }
      }
    }

    // Detect an unsafe fixed-offset read in this operand.
    if (hasUnsafeRead(Op, PtrDecl, C)) {
      if (!SepChecked) {
        reportBug(C);
        return;
      }
    }
  }
}

//===----------------------------------------------------------------------===//
// Checker Registration
//===----------------------------------------------------------------------===//

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects out-of-bounds read when delimiter may be NUL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
