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
#include "llvm/ADT/SmallVector.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

/// \brief Strip parentheses and implicit casts from an expression.
static const Expr *unwrapExpr(const Expr *E) {
  if (!E)
    return nullptr;
  return E->IgnoreParenImpCasts();
}

/// \brief Check whether \p Sub is a subscript of pointer \p P at index 0.
static bool isP0Subscript(const ArraySubscriptExpr *Sub, const VarDecl *P,
                          CheckerContext &C) {
  const Expr *Base = Sub->getBase()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(Base);
  if (!DRE || DRE->getDecl() != P)
    return false;

  llvm::APSInt IdxVal;
  if (!EvaluateExprToInt(IdxVal, Sub->getIdx(), C))
    return false;
  return IdxVal.getSExtValue() == 0;
}

/// \brief Check whether \p E is an expression of the form \p P[0].
static bool isP0SubscriptExpr(const Expr *E, const VarDecl *P,
                              CheckerContext &C) {
  E = unwrapExpr(E);
  if (const auto *Sub = dyn_cast<ArraySubscriptExpr>(E))
    return isP0Subscript(Sub, P, C);
  return false;
}

/// \brief Check whether \p S contains an assignment of \p P[0] to variable \p V.
static bool containsAssignmentToVFromP0(const Stmt *S, const VarDecl *V,
                                        const VarDecl *P, CheckerContext &C) {
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (DRE->getDecl() == V && isP0SubscriptExpr(RHS, P, C))
          return true;
      }
    }
  }

  if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      if (const auto *VD = dyn_cast<VarDecl>(D)) {
        if (VD == V) {
          const Expr *Init = VD->getInit();
          if (Init && isP0SubscriptExpr(Init, P, C))
            return true;
        }
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (containsAssignmentToVFromP0(Child, V, P, C))
      return true;
  }
  return false;
}

/// \brief Check whether variable \p V is assigned \p P[0] before \p If.
static bool isVarAssignedP0Before(const VarDecl *V, const VarDecl *P,
                                  const CompoundStmt *CS, const IfStmt *If,
                                  CheckerContext &C) {
  for (const Stmt *S : CS->body()) {
    if (S == If)
      break;
    if (containsAssignmentToVFromP0(S, V, P, C))
      return true;
  }
  return false;
}

/// \brief Check whether \p E is a non-NUL check on \p P[0], either directly
///        (e.g. `ptr[0]`) or through a variable assigned from \p P[0].
static bool isNonNullCheckExpr(const Expr *E, const VarDecl *P,
                               const CompoundStmt *CS, const IfStmt *If,
                               CheckerContext &C) {
  E = unwrapExpr(E);

  if (const auto *Sub = dyn_cast<ArraySubscriptExpr>(E)) {
    if (isP0Subscript(Sub, P, C))
      return true;
  }

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    const VarDecl *V = dyn_cast<VarDecl>(DRE->getDecl());
    if (V && isVarAssignedP0Before(V, P, CS, If, C))
      return true;
  }

  return false;
}

/// \brief Check whether \p E is a constant zero (0, '\0', NULL, etc.).
static bool isZeroConstant(const Expr *E, CheckerContext &C) {
  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, E, C))
    return Val.getSExtValue() == 0;

  if (E->isNullPointerConstant(C.getASTContext(),
                               Expr::NPC_ValueDependentIsNull))
    return true;

  return false;
}

/// \brief Check whether \p E is a guard on \p P[0] before the relevant access.
///        Forms handled: `x`, `x != 0`, `0 != x`, where `x` is `P[0]` or a
///        variable assigned from `P[0]`.
static bool isGuardOnP0(const Expr *E, const VarDecl *P,
                        const CompoundStmt *CS, const IfStmt *If,
                        CheckerContext &C) {
  E = unwrapExpr(E);

  if (isNonNullCheckExpr(E, P, CS, If, C))
    return true;

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      if (isZeroConstant(LHS, C) && isNonNullCheckExpr(RHS, P, CS, If, C))
        return true;
      if (isZeroConstant(RHS, C) && isNonNullCheckExpr(LHS, P, CS, If, C))
        return true;
    }
  }

  return false;
}

/// \brief Flatten a logical AND chain into an ordered list of operands.
static void flattenAnd(const Expr *E, SmallVectorImpl<const Expr *> &Out) {
  E = unwrapExpr(E);

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      flattenAnd(BO->getLHS(), Out);
      flattenAnd(BO->getRHS(), Out);
      return;
    }
  }

  Out.push_back(E);
}

/// \brief Check whether \p P is initialized by a call to a `string_search` role.
static bool isInitializedFromStringSearch(const VarDecl *P, CheckerContext &C) {
  const Expr *Init = P->getInit();
  if (!Init)
    return false;

  Init = unwrapExpr(Init);
  if (const auto *CE = dyn_cast<CallExpr>(Init)) {
    return knighter::callExprIsRole(CE, "string_search", C.getASTContext());
  }

  return false;
}

/// \brief Check whether statement \p S contains an increment of pointer \p P.
static bool containsIncrementOf(const Stmt *S, const VarDecl *P) {
  if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        if (DRE->getDecl() == P)
          return true;
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (containsIncrementOf(Child, P))
      return true;
  }
  return false;
}

/// \brief Check whether \p P is incremented before \p If.
static bool isIncrementedBefore(const VarDecl *P, const CompoundStmt *CS,
                                const IfStmt *If) {
  for (const Stmt *S : CS->body()) {
    if (S == If)
      break;
    if (containsIncrementOf(S, P))
      return true;
  }
  return false;
}

/// \brief Check whether \p Sub is a candidate subscript for the out-of-bounds bug.
static bool isCandidateSub(const ArraySubscriptExpr *Sub, CheckerContext &C,
                           const CompoundStmt *CS, const IfStmt *If) {
  const Expr *Base = Sub->getBase()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(Base);
  if (!DRE)
    return false;

  const VarDecl *P = dyn_cast<VarDecl>(DRE->getDecl());
  if (!P || !P->getType()->isPointerType())
    return false;

  llvm::APSInt IdxVal;
  if (!EvaluateExprToInt(IdxVal, Sub->getIdx(), C))
    return false;
  if (IdxVal.getSExtValue() < 1)
    return false;

  if (!isInitializedFromStringSearch(P, C))
    return false;

  if (!isIncrementedBefore(P, CS, If))
    return false;

  return true;
}

/// \brief Recursively find the first candidate ArraySubscriptExpr in a statement.
static const ArraySubscriptExpr *findCandidateSub(const Stmt *S,
                                                  CheckerContext &C,
                                                  const CompoundStmt *CS,
                                                  const IfStmt *If) {
  if (const auto *Sub = dyn_cast<ArraySubscriptExpr>(S)) {
    if (isCandidateSub(Sub, C, CS, If))
      return Sub;
  }

  for (const Stmt *Child : S->children()) {
    if (const auto *Res = findCandidateSub(Child, C, CS, If))
      return Res;
  }

  return nullptr;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read", "Memory access")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                           CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const IfStmt *TargetIf = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!TargetIf)
    return;

  const CompoundStmt *ParentCS =
      findSpecificTypeInParents<CompoundStmt>(TargetIf, C);
  if (!ParentCS)
    return;

  SmallVector<const Expr *, 8> Operands;
  flattenAnd(CondE, Operands);

  for (unsigned i = 0; i < Operands.size(); ++i) {
    const Expr *Op = Operands[i];
    const ArraySubscriptExpr *Sub =
        findCandidateSub(Op, C, ParentCS, TargetIf);
    if (!Sub)
      continue;

    const VarDecl *P = nullptr;
    if (const auto *DRE =
            dyn_cast<DeclRefExpr>(Sub->getBase()->IgnoreParenImpCasts()))
      P = dyn_cast<VarDecl>(DRE->getDecl());
    if (!P)
      continue;

    bool Guarded = false;
    for (unsigned j = 0; j < i; ++j) {
      if (isGuardOnP0(Operands[j], P, ParentCS, TargetIf, C)) {
        Guarded = true;
        break;
      }
    }

    if (Guarded)
      continue;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Out-of-bounds read: pointer advanced past string_search delimiter "
        "without checking for NUL",
        N);
    Report->addRange(Sub->getSourceRange());
    C.emitReport(std::move(Report));
    return;
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects out-of-bounds read after advancing a pointer returned by "
      "string_search without checking for NUL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "string_search": {"names": ["strchr"], "description": "finds the first occurrence of a character in a NUL-terminated string and returns a pointer to it or NULL"},
  "character_classifier": {"names": ["ISDIGIT"], "description": "macro or function that classifies a character, e.g., tests if it is a digit"}
}
*/
