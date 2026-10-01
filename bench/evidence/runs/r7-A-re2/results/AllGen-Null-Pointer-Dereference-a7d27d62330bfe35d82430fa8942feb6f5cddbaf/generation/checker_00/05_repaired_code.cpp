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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class AssignmentFinder : public RecursiveASTVisitor<AssignmentFinder> {
public:
  explicit AssignmentFinder(const VarDecl *Target)
      : Target(Target), FoundAny(false), FoundNonNull(false) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Assign)
      return true;
    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS);
    if (!DRE)
      return true;
    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (VD != Target)
      return true;

    FoundAny = true;
    const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
    ASTContext &Ctx = Target->getASTContext();
    if (!RHS->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull))
      FoundNonNull = true;
    return true;
  }

  bool FoundAny;
  bool FoundNonNull;

private:
  const VarDecl *Target;
};

class NullInitPtrVarCollector : public RecursiveASTVisitor<NullInitPtrVarCollector> {
public:
  explicit NullInitPtrVarCollector(ASTContext &Ctx) : Ctx(Ctx) {}

  bool VisitVarDecl(VarDecl *VD) {
    if (VD->getType()->isPointerType() && VD->hasInit()) {
      const Expr *Init = VD->getInit();
      if (Init->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull))
        Vars.push_back(VD);
    }
    return true;
  }

  std::vector<const VarDecl *> Vars;

private:
  ASTContext &Ctx;
};

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Null return from factory for empty input",
                       "Null Dereference")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                           CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  Cond = Cond->IgnoreParenImpCasts();

  bool Negated = false;
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      Negated = true;
      Cond = UO->getSubExpr()->IgnoreParenImpCasts();
    }
  }

  const CXXMemberCallExpr *MCE = dyn_cast<CXXMemberCallExpr>(Cond);
  if (!MCE)
    return;

  const CXXMethodDecl *MD = MCE->getMethodDecl();
  if (!MD || MD->getNameAsString() != "empty")
    return;

  const Expr *Obj = MCE->getImplicitObjectArgument();
  if (!Obj)
    return;
  Obj = Obj->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Obj);
  if (!DRE)
    return;
  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD)
    return;

  const FunctionDecl *FD =
      dyn_cast<FunctionDecl>(C.getCurrentAnalysisDeclContext()->getDecl());
  if (!FD)
    return;
  if (!FD->getReturnType()->isPointerType())
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Stmt *NonEmptyBranch = Negated ? IS->getThen() : IS->getElse();
  const Stmt *EmptyBranch = Negated ? IS->getElse() : IS->getThen();
  if (!NonEmptyBranch)
    return;

  NullInitPtrVarCollector Collector(C.getASTContext());
  Collector.TraverseStmt(const_cast<Stmt *>(FD->getBody()));
  if (Collector.Vars.empty())
    return;

  const CompoundStmt *Body = dyn_cast<CompoundStmt>(FD->getBody());
  if (!Body)
    return;

  std::vector<const Stmt *> Children;
  for (const Stmt *Child : Body->body())
    Children.push_back(Child);

  int ISIndex = -1;
  for (unsigned i = 0; i < Children.size(); ++i) {
    if (const IfStmt *ChildIS = dyn_cast<IfStmt>(Children[i])) {
      if (ChildIS == IS) {
        ISIndex = i;
        break;
      }
    }
  }
  if (ISIndex == -1)
    return;

  for (const VarDecl *VD : Collector.Vars) {
    // The variable must be local to the analyzed function.
    if (VD->getDeclContext() != FD)
      continue;

    // The non-empty branch must assign a non-null value to the pointer.
    AssignmentFinder NonEmptyFinder(VD);
    NonEmptyFinder.TraverseStmt(const_cast<Stmt *>(NonEmptyBranch));
    if (!NonEmptyFinder.FoundNonNull)
      continue;

    // The empty branch must not assign to the pointer at all.
    if (EmptyBranch) {
      AssignmentFinder EmptyFinder(VD);
      EmptyFinder.TraverseStmt(const_cast<Stmt *>(EmptyBranch));
      if (EmptyFinder.FoundAny)
        continue;
    }

    // Locate the declaration of the pointer variable in the function body.
    int DeclIndex = -1;
    for (unsigned i = 0; i < Children.size(); ++i) {
      if (const DeclStmt *DS = dyn_cast<DeclStmt>(Children[i])) {
        for (const Decl *D : DS->decls()) {
          if (D == VD) {
            DeclIndex = i;
            break;
          }
        }
      }
      if (DeclIndex != -1)
        break;
    }
    if (DeclIndex == -1 || DeclIndex >= ISIndex)
      continue;

    // Ensure the pointer is returned after the IfStmt (i.e. on the empty path).
    bool FoundReturn = false;
    for (unsigned i = ISIndex + 1; i < Children.size(); ++i) {
      const ReturnStmt *RS = dyn_cast<ReturnStmt>(Children[i]);
      if (!RS)
        continue;
      const Expr *RetVal = RS->getRetValue();
      if (!RetVal)
        continue;
      RetVal = RetVal->IgnoreParenImpCasts();
      if (const DeclRefExpr *RetDRE = dyn_cast<DeclRefExpr>(RetVal)) {
        if (const VarDecl *RetVD = dyn_cast<VarDecl>(RetDRE->getDecl())) {
          if (RetVD == VD) {
            FoundReturn = true;
            break;
          }
        }
      }
    }
    if (!FoundReturn)
      continue;

    // Pattern confirmed: report the bug.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Function returns NULL for empty input; callers may dereference NULL.",
        N);
    Report->addRange(IS->getSourceRange());
    C.emitReport(std::move(Report));
    return;
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects factory/helper functions that return NULL for empty input while "
      "callers expect a valid pointer",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
