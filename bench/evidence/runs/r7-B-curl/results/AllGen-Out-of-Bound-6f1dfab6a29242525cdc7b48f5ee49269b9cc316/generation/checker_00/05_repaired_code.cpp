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
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool isPositiveInteger(const Expr *E, ASTContext &Ctx) {
  E = E->IgnoreParenImpCasts();
  Expr::EvalResult Res;
  if (!E->EvaluateAsInt(Res, Ctx))
    return false;
  return Res.Val.getInt().isStrictlyPositive();
}

static bool isCallTo(const Expr *E, StringRef Name, CheckerContext &C) {
  E = E->IgnoreParenImpCasts();
  const CallExpr *CE = dyn_cast<CallExpr>(E);
  if (!CE)
    return false;
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    return FD->getName() == Name;
  }
  return ExprHasName(CE, Name, C);
}

static const VarDecl *findUnsafeSubscriptVar(const Stmt *S, ASTContext &Ctx) {
  if (!S)
    return nullptr;
  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(S)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base)) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (isPositiveInteger(ASE->getIdx(), Ctx))
          return VD;
      }
    }
  }
  for (const Stmt *Child : S->children()) {
    if (const VarDecl *VD = findUnsafeSubscriptVar(Child, Ctx))
      return VD;
  }
  return nullptr;
}

static bool isIncrementOf(const Stmt *S, const VarDecl *P, ASTContext &Ctx) {
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub))
        return DRE->getDecl() == P;
    }
  }
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_AddAssign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (DRE->getDecl() == P) {
          Expr::EvalResult Res;
          if (BO->getRHS()->EvaluateAsInt(Res, Ctx)) {
            return Res.Val.getInt() == 1;
          }
        }
      }
    }
  }
  return false;
}

static const VarDecl *getSeparatorVar(const Stmt *S, const VarDecl *P,
                                      ASTContext &Ctx) {
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || BO->getOpcode() != BO_Assign)
    return nullptr;
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const VarDecl *LVar = nullptr;
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
    LVar = dyn_cast<VarDecl>(DRE->getDecl());
  }
  if (!LVar)
    return nullptr;
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  // Check P[0]
  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(RHS)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base)) {
      if (DRE->getDecl() == P) {
        Expr::EvalResult Res;
        if (ASE->getIdx()->EvaluateAsInt(Res, Ctx) && Res.Val.getInt().isZero())
          return LVar;
      }
    }
  }
  // Check *P
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(RHS)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        if (DRE->getDecl() == P)
          return LVar;
      }
    }
  }
  return nullptr;
}

static bool isZeroConstant(const Expr *E, ASTContext &Ctx) {
  Expr::EvalResult Res;
  if (E->EvaluateAsInt(Res, Ctx))
    return Res.Val.getInt().isZero();
  return false;
}

static bool isGuardFor(const Stmt *S, const VarDecl *Sep, ASTContext &Ctx) {
  const Expr *E = dyn_cast<Expr>(S);
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  // Case: sep
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == Sep;
  }
  // Case: sep != 0, 0 != sep
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      auto isSep = [&](const Expr *X) {
        if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(X))
          return DRE->getDecl() == Sep;
        return false;
      };
      if ((isSep(LHS) && isZeroConstant(RHS, Ctx)) ||
          (isZeroConstant(LHS, Ctx) && isSep(RHS)))
        return true;
    }
  }
  return false;
}

static bool containsUnsafeSubscript(const Stmt *S, const VarDecl *P,
                                    ASTContext &Ctx) {
  if (!S)
    return false;
  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(S)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base)) {
      if (DRE->getDecl() == P) {
        if (isPositiveInteger(ASE->getIdx(), Ctx))
          return true;
      }
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsUnsafeSubscript(Child, P, Ctx))
      return true;
  }
  return false;
}

static void flattenLAnd(const Expr *E,
                        llvm::SmallVectorImpl<const Expr *> &Ops) {
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

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked lookahead after strchr delimiter",
                       "Logic Error")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportBug(const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;
  ASTContext &Ctx = C.getASTContext();

  // Find an unsafe subscript in the condition to get the pointer variable.
  const VarDecl *P = findUnsafeSubscriptVar(Condition, Ctx);
  if (!P)
    return;

  // Check that P is initialized from strchr.
  const Expr *Init = P->getInit();
  if (!Init || !isCallTo(Init, "strchr", C))
    return;

  // Find the enclosing IfStmt.
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  // Find the enclosing CompoundStmt of the IfStmt.
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
  if (!CS)
    return;

  // Scan statements before the IfStmt for increment of P and assignment to
  // separator.
  const VarDecl *Sep = nullptr;
  bool foundIncrement = false;
  for (const Stmt *S : CS->body()) {
    if (S == IS)
      break;
    if (!foundIncrement) {
      if (isIncrementOf(S, P, Ctx)) {
        foundIncrement = true;
        continue;
      }
    }
    if (foundIncrement && !Sep) {
      if (const VarDecl *V = getSeparatorVar(S, P, Ctx)) {
        Sep = V;
        break;
      }
    }
  }
  if (!foundIncrement || !Sep)
    return;

  // Flatten the condition's top-level && operands.
  llvm::SmallVector<const Expr *, 8> Ops;
  flattenLAnd(CondE, Ops);

  bool foundUnsafe = false;
  bool guarded = false;
  for (const Expr *Op : Ops) {
    if (!foundUnsafe) {
      if (containsUnsafeSubscript(Op, P, Ctx)) {
        foundUnsafe = true;
        if (guarded)
          return; // already guarded before this operand
        break;    // unsafe without preceding guard
      }
    }
    if (isGuardFor(Op, Sep, Ctx)) {
      guarded = true;
    }
  }

  if (foundUnsafe && !guarded) {
    reportBug(IS, C);
  }
}

void SAGenTestChecker::reportBug(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unchecked lookahead after strchr delimiter; missing non-NUL check for "
      "separator before reading past it.",
      N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked lookahead after strchr delimiter in C strings",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
