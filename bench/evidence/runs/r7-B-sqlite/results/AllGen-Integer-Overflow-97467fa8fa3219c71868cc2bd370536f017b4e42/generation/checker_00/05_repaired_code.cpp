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
#include "clang/AST/Type.h"
#include "clang/AST/OperationKinds.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Checks whether an expression is a DeclRefExpr referring to a variable with
// the given name.
static bool isDeclRefNamed(const Expr *E, StringRef Name) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const ValueDecl *VD = DRE->getDecl())
      return VD->getName() == Name;
  }
  return false;
}

// Matches the late bounds check: j + n > nOut (or >=).
static bool isLateBoundsCheckCondition(const Expr *Cond) {
  if (!Cond)
    return false;
  Cond = Cond->IgnoreParenImpCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return false;
  if (BO->getOpcode() != BO_GT && BO->getOpcode() != BO_GE)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  if (!isDeclRefNamed(RHS, "nOut"))
    return false;

  const BinaryOperator *Add = dyn_cast<BinaryOperator>(LHS);
  if (!Add || Add->getOpcode() != BO_Add)
    return false;

  return isDeclRefNamed(Add->getLHS(), "n") ||
         isDeclRefNamed(Add->getRHS(), "n");
}

// Matches the early overflow guard: n > nOut (or >=), or nOut < n.
static bool isEarlyGuardCondition(const Expr *Cond) {
  if (!Cond)
    return false;
  Cond = Cond->IgnoreParenImpCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return false;
  if (BO->getOpcode() != BO_GT && BO->getOpcode() != BO_GE)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  if (isDeclRefNamed(LHS, "n") && isDeclRefNamed(RHS, "nOut"))
    return true;
  if (isDeclRefNamed(RHS, "n") && isDeclRefNamed(LHS, "nOut"))
    return true;
  return false;
}

// Returns true if the statement subtree contains a return statement.
static bool containsReturn(const Stmt *S) {
  if (!S)
    return false;
  if (isa<ReturnStmt>(S))
    return true;
  for (const Stmt *Child : S->children()) {
    if (containsReturn(Child))
      return true;
  }
  return false;
}

// AST visitor that gathers the information needed to decide whether the
// vulnerable pattern is present.
class KvvfsDecodeVisitor : public RecursiveASTVisitor<KvvfsDecodeVisitor> {
public:
  const VarDecl *NDecl = nullptr;
  const VarDecl *MultDecl = nullptr;
  bool HasNAdd = false;
  bool HasMultMul = false;
  bool HasEarlyGuard = false;
  bool MemsetUsesN = false;

  bool VisitVarDecl(VarDecl *VD) {
    if (VD->getName() == "n")
      NDecl = VD;
    if (VD->getName() == "mult")
      MultDecl = VD;
    return true;
  }

  bool VisitCompoundAssignOperator(CompoundAssignOperator *CAO) {
    if (CAO->getOpcode() == BO_AddAssign &&
        isDeclRefNamed(CAO->getLHS(), "n"))
      HasNAdd = true;
    if (CAO->getOpcode() == BO_MulAssign &&
        isDeclRefNamed(CAO->getLHS(), "mult"))
      HasMultMul = true;
    return true;
  }

  bool VisitIfStmt(IfStmt *IS) {
    if (HasEarlyGuard)
      return true;
    if (IS->getCond() && isEarlyGuardCondition(IS->getCond())) {
      if (containsReturn(IS->getThen()))
        HasEarlyGuard = true;
    }
    return true;
  }

  bool VisitCallExpr(CallExpr *CE) {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (FD && FD->getName() == "memset") {
      if (CE->getNumArgs() >= 3) {
        if (isDeclRefNamed(CE->getArg(2), "n"))
          MemsetUsesN = true;
      }
    }
    return true;
  }
};

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow", "Memory Safety")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return;

  const Decl *D = LCtx->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || FD->getName() != "kvvfsDecode")
    return;

  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond || !isLateBoundsCheckCondition(Cond))
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  KvvfsDecodeVisitor V;
  V.TraverseStmt(const_cast<Stmt *>(Body));

  // If the early overflow guard is present, the code is safe.
  if (V.HasEarlyGuard)
    return;

  if (!V.NDecl || !V.MultDecl)
    return;
  if (!V.NDecl->getType()->isSpecificBuiltinType(BuiltinType::Int))
    return;
  if (!V.MultDecl->getType()->isSpecificBuiltinType(BuiltinType::Int))
    return;
  if (!V.HasNAdd || !V.HasMultMul)
    return;
  if (!V.MemsetUsesN)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Potential integer overflow in length calculation before memset", N);
  Report->addRange(Cond->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked integer overflow in kvvfsDecode length calculation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
