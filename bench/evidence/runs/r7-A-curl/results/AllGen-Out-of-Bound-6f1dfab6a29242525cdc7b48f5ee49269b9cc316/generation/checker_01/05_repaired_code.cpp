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

#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

//===----------------------------------------------------------------------===//
// Helper functions for AST pattern matching
//===----------------------------------------------------------------------===//

/// \brief Check if an expression is a call to strchr.
static bool isStrchrCall(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  const auto *CE = dyn_cast<CallExpr>(E);
  if (!CE)
    return false;
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return false;
  return FD->getName() == "strchr";
}

/// \brief If S is an increment (++ptr or ptr++), return the incremented VarDecl.
static const VarDecl *getIncrementedVar(const Stmt *S) {
  if (!S)
    return nullptr;

  if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->isIncrementOp()) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
          return VD;
      }
    }
  }
  return nullptr;
}

/// \brief Check if E is exactly ptr[0].
static bool isPtrZeroSubscript(const Expr *E, const VarDecl *Ptr) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  const auto *ASE = dyn_cast<ArraySubscriptExpr>(E);
  if (!ASE)
    return false;

  const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(Base);
  if (!DRE || DRE->getDecl() != Ptr)
    return false;

  const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();
  if (const auto *IL = dyn_cast<IntegerLiteral>(Idx))
    return IL->getValue() == 0;

  return false;
}

/// \brief If S assigns ptr[0] to a variable, return that variable's VarDecl.
static const VarDecl *getSepFromAssignment(const Stmt *S, const VarDecl *Ptr) {
  if (!S)
    return nullptr;

  // Case 1: sep = ptr[0];
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (isPtrZeroSubscript(RHS, Ptr)) {
        if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
          if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
            return VD;
        }
      }
    }
  }

  // Case 2: char sep = ptr[0];
  if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      if (const auto *VD = dyn_cast<VarDecl>(D)) {
        if (VD->hasInit() && isPtrZeroSubscript(VD->getInit(), Ptr))
          return VD;
      }
    }
  }
  return nullptr;
}

/// \brief Flatten a logical && chain into its operands (left to right).
static void flattenAnd(const Expr *E,
                       llvm::SmallVectorImpl<const Expr *> &Ops) {
  if (!E)
    return;
  E = E->IgnoreParenImpCasts();
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      flattenAnd(BO->getLHS(), Ops);
      flattenAnd(BO->getRHS(), Ops);
      return;
    }
  }
  Ops.push_back(E);
}

/// \brief Check if E is a guard on Sep (e.g., `sep` or `sep != 0`).
static bool isGuardOnSep(const Expr *E, const VarDecl *Sep) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  // Case: sep
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    return DRE->getDecl() == Sep;

  // Case: sep != 0
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      auto isZero = [](const Expr *Z) -> bool {
        if (const auto *IL = dyn_cast<IntegerLiteral>(Z))
          return IL->getValue() == 0;
        if (const auto *CL = dyn_cast<CharacterLiteral>(Z))
          return CL->getValue() == 0;
        return false;
      };

      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (DRE->getDecl() == Sep && isZero(RHS))
          return true;
      }
      if (const auto *DRE = dyn_cast<DeclRefExpr>(RHS)) {
        if (DRE->getDecl() == Sep && isZero(LHS))
          return true;
      }
    }
  }
  return false;
}

/// \brief Recursively search for an out-of-bounds subscript on Ptr (index >= 1).
static bool containsUnsafeSubscript(const Expr *E, const VarDecl *Ptr) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      if (DRE->getDecl() == Ptr) {
        const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();
        if (const auto *IL = dyn_cast<IntegerLiteral>(Idx)) {
          if (IL->getValue() != 0)
            return true;
        }
      }
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child)) {
      if (containsUnsafeSubscript(ChildE, Ptr))
        return true;
    }
  }
  return false;
}

//===----------------------------------------------------------------------===//
// Main checker class
//===----------------------------------------------------------------------===//

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read", "Memory safety")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
    const Expr *CondE = dyn_cast<Expr>(Condition);
    if (!CondE)
      return;

    // Find the enclosing IfStmt and the nearest CompoundStmt (the block
    // that contains the IfStmt).
    const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
    const CompoundStmt *CS =
        findSpecificTypeInParents<CompoundStmt>(Condition, C);
    if (!IS || !CS)
      return;

    // Locate the IfStmt inside the CompoundStmt.
    unsigned idx = 0;
    bool found = false;
    for (auto *S : CS->body()) {
      if (S == IS) {
        found = true;
        break;
      }
      idx++;
    }
    if (!found)
      return;

    const VarDecl *PtrVar = nullptr;
    const VarDecl *SepVar = nullptr;

    // Scan statements before the IfStmt to find:
    //   ptr++ ;          -> PtrVar
    //   sep = ptr[0] ;   -> SepVar
    unsigned i = 0;
    for (const Stmt *S : CS->body()) {
      if (i >= idx)
        break;
      if (!PtrVar)
        PtrVar = getIncrementedVar(S);
      if (PtrVar && !SepVar)
        SepVar = getSepFromAssignment(S, PtrVar);
      ++i;
    }

    if (!PtrVar || !SepVar)
      return;
    if (!PtrVar->getType()->isPointerType())
      return;

    // Analyse the branch condition.
    llvm::SmallVector<const Expr *, 8> Ops;
    flattenAnd(CondE, Ops);

    bool sepChecked = false;
    for (const Expr *Op : Ops) {
      if (isGuardOnSep(Op, SepVar)) {
        sepChecked = true;
        continue;
      }
      if (containsUnsafeSubscript(Op, PtrVar)) {
        if (!sepChecked) {
          ExplodedNode *N = C.generateNonFatalErrorNode();
          if (!N)
            return;
          auto report = std::make_unique<PathSensitiveBugReport>(
              *BT,
              "Out-of-bounds read: pointer advanced past delimiter without "
              "checking for NUL",
              N);
          report->addRange(Condition->getSourceRange());
          C.emitReport(std::move(report));
          return;
        }
      }
    }
  }
};

} // end anonymous namespace

//===----------------------------------------------------------------------===//
// Checker registration
//===----------------------------------------------------------------------===//

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects out-of-bounds read after advancing past a delimiter without "
      "checking for NUL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
