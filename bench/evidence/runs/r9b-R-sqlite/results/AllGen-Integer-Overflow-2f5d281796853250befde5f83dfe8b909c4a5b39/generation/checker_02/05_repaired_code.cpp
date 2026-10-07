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
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

//===----------------------------------------------------------------------===//
// Helper functions
//===----------------------------------------------------------------------===//

static bool isArithmeticOp(BinaryOperator::Opcode Op) {
  switch (Op) {
    case BO_Add:
    case BO_Sub:
    case BO_Mul:
    case BO_Div:
    case BO_Rem:
    case BO_Shl:
    case BO_Shr:
      return true;
    default:
      return false;
  }
}

// Collect all DeclRefExpr VarDecls in a subtree.
static void collectDeclRefs(const Stmt *S,
                            llvm::SmallPtrSetImpl<const VarDecl *> &Vars) {
  if (!S)
    return;
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      Vars.insert(VD);
  }
  for (const Stmt *Child : S->children())
    collectDeclRefs(Child, Vars);
}

// Collect variables used anywhere inside a ForStmt.
static void collectLoopVars(const Stmt *S,
                            llvm::SmallPtrSetImpl<const VarDecl *> &Vars) {
  if (!S)
    return;
  if (const ForStmt *FS = dyn_cast<ForStmt>(S)) {
    collectDeclRefs(FS->getInit(), Vars);
    collectDeclRefs(FS->getCond(), Vars);
    collectDeclRefs(FS->getInc(), Vars);
    collectDeclRefs(FS->getBody(), Vars);
    return; // whole subtree already traversed
  }
  for (const Stmt *Child : S->children())
    collectLoopVars(Child, Vars);
}

static bool isLoopCounterOrIndex(const VarDecl *VD, const FunctionDecl *FD) {
  if (!VD || !FD || !FD->getBody())
    return false;
  llvm::SmallPtrSet<const VarDecl *, 16> Vars;
  collectLoopVars(FD->getBody(), Vars);
  return Vars.count(VD) > 0;
}

static bool containsLoopCounter(const Stmt *S, const FunctionDecl *FD) {
  if (!S)
    return false;
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (isLoopCounterOrIndex(VD, FD))
        return true;
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsLoopCounter(Child, FD))
      return true;
  }
  return false;
}

static bool isNarrowArithmeticWithLoopCounter(const Expr *E,
                                               const FunctionDecl *FD,
                                               ASTContext &Ctx) {
  if (!E)
    return false;
  const Expr *Expr = E->IgnoreParenImpCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Expr);
  if (!BO)
    return false;
  if (!isArithmeticOp(BO->getOpcode()))
    return false;
  QualType Ty = BO->getType();
  if (!Ty->isSignedIntegerType())
    return false;
  if (Ctx.getIntWidth(Ty) >= 64)
    return false;
  return containsLoopCounter(BO, FD);
}

static bool containsAbortingAssert(const Stmt *S, ASTContext &Ctx) {
  if (!S)
    return false;
  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (knighter::callExprIsRole(CE, "aborting_assert", Ctx))
      return true;
  }
  for (const Stmt *Child : S->children()) {
    if (containsAbortingAssert(Child, Ctx))
      return true;
  }
  return false;
}

static void findAndReportOverflow(const Expr *E,
                                  const FunctionDecl *FD,
                                  ASTContext &Ctx,
                                  CheckerContext &C,
                                  const BugType *BT) {
  if (!E)
    return;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_LE || Op == BO_LT || Op == BO_GE || Op == BO_GT ||
        Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool L64 = LHS->getType()->isIntegerType() &&
                 Ctx.getIntWidth(LHS->getType()) >= 64;
      bool R64 = RHS->getType()->isIntegerType() &&
                 Ctx.getIntWidth(RHS->getType()) >= 64;
      bool LBad = isNarrowArithmeticWithLoopCounter(LHS, FD, Ctx);
      bool RBad = isNarrowArithmeticWithLoopCounter(RHS, FD, Ctx);
      if ((L64 && RBad) || (R64 && LBad)) {
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N)
          return;
        auto report = std::make_unique<PathSensitiveBugReport>(
            *BT, "signed integer overflow in assert", N);
        report->addRange(BO->getSourceRange());
        C.emitReport(std::move(report));
        return;
      }
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child))
      findAndReportOverflow(ChildE, FD, Ctx, C, BT);
  }
}

//===----------------------------------------------------------------------===//
// Checker class
//===----------------------------------------------------------------------===//

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow in Assert",
                       "Integer Overflow")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *If = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!If)
    return;

  ASTContext &Ctx = C.getASTContext();
  if (!containsAbortingAssert(If->getThen(), Ctx) &&
      !containsAbortingAssert(If->getElse(), Ctx))
    return;

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(
      C.getCurrentAnalysisDeclContext()->getDecl());
  if (!FD)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  findAndReportOverflow(CondE, FD, Ctx, C, BT.get());
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects signed integer overflow in assert conditions due to narrow "
      "loop counter arithmetic",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "aborting_assert": {
    "names": ["assert"],
    "description": "Macro that aborts execution when its condition is false."
  },
  "length_of": {
    "names": ["sqlite3_value_bytes"],
    "description": "Returns the length in bytes of a value; used to compute size bounds."
  }
}
*/
