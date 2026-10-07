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

#include "llvm/ADT/SmallVector.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks local variables that currently own a heap resource.
// true  -> must be deallocated or transferred by a container_insert call.
// false -> ownership has been released or transferred.
REGISTER_MAP_WITH_PROGRAMSTATE(OwnedVars, const VarDecl *, bool)

namespace {

static const VarDecl *getArgVarDecl(const Expr *Arg) {
  if (!Arg)
    return nullptr;

  Arg = Arg->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(Arg)) {
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (VD && VD->isLocalVarDecl())
      return VD;
  }
  return nullptr;
}

static const VarDecl *getAssignedVarDecl(const CallEvent &Call,
                                         CheckerContext &C) {
  const Expr *CallE = Call.getOriginExpr();
  if (!CallE)
    return nullptr;

  CallE = CallE->IgnoreParenImpCasts();

  // Direct assignment: p = duplicator(...);
  if (const auto *BO = findSpecificTypeInParents<BinaryOperator>(CallE, C)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (RHS == CallE)
        return getArgVarDecl(BO->getLHS());
    }
  }

  // Declaration initialization: T *p = duplicator(...);
  if (const auto *DS = findSpecificTypeInParents<DeclStmt>(CallE, C)) {
    for (const Decl *D : DS->decls()) {
      if (const auto *VD = dyn_cast<VarDecl>(D)) {
        if (VD->hasInit()) {
          const Expr *Init = VD->getInit()->IgnoreParenImpCasts();
          if (Init == CallE)
            return VD;
        }
      }
    }
  }

  return nullptr;
}

static void collectNonNullTests(const Expr *Cond,
                                llvm::SmallVectorImpl<const Expr *> &Out,
                                ASTContext &Ctx) {
  if (!Cond)
    return;

  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_LAnd) {
      collectNonNullTests(BO->getLHS(), Out, Ctx);
      collectNonNullTests(BO->getRHS(), Out, Ctx);
      return;
    }

    if (BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSIsNull =
          LHS->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull =
          RHS->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull && !RHSIsNull)
        Out.push_back(RHS);
      else if (RHSIsNull && !LHSIsNull)
        Out.push_back(LHS);
      return;
    }

    if (BO->getOpcode() == BO_EQ)
      return;
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot)
      return;
  }

  Out.push_back(Cond);
}

static bool callHasArgVarDecl(const CallExpr *CE, const VarDecl *VD) {
  if (!CE || !VD)
    return false;

  for (unsigned I = 0; I < CE->getNumArgs(); ++I) {
    if (getArgVarDecl(CE->getArg(I)) == VD)
      return true;
  }
  return false;
}

class RoleArgFinder : public RecursiveASTVisitor<RoleArgFinder> {
  StringRef Role;
  const VarDecl *Target;
  ASTContext &Ctx;
  bool Found = false;

public:
  RoleArgFinder(StringRef R, const VarDecl *T, ASTContext &C)
      : Role(R), Target(T), Ctx(C) {}

  bool VisitCallExpr(CallExpr *CE) {
    if (Found)
      return true;

    if (knighter::callExprIsRole(CE, Role, Ctx)) {
      if (callHasArgVarDecl(CE, Target))
        Found = true;
    }
    return true;
  }

  bool found() const { return Found; }
};

static bool thenTransfers(const Stmt *Then, const VarDecl *Res,
                          CheckerContext &C) {
  if (!Then || !Res)
    return false;

  RoleArgFinder Finder("container_insert", Res, C.getASTContext());
  Finder.TraverseStmt(const_cast<Stmt *>(Then));
  return Finder.found();
}

static bool elseDeallocates(const Stmt *Else, const VarDecl *Res,
                            CheckerContext &C) {
  if (!Else || !Res)
    return false;

  RoleArgFinder Finder("deallocator", Res, C.getASTContext());
  Finder.TraverseStmt(const_cast<Stmt *>(Else));
  return Finder.found();
}

class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Resource Leak", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportLeak(const IfStmt *IS, const VarDecl *Res,
                  CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!(knighter::callIsRole(Call, "duplicator") ||
        knighter::callIsRole(Call, "allocator") ||
        knighter::callIsRole(Call, "container_insert"))) {
    return;
  }

  const VarDecl *VD = getAssignedVarDecl(Call, C);
  if (!VD)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<OwnedVars>(VD, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  bool IsDeallocator = knighter::callIsRole(Call, "deallocator");
  bool IsInsert = knighter::callIsRole(Call, "container_insert");

  if (!IsDeallocator && !IsInsert)
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    const Expr *Arg = Call.getArgExpr(I);
    if (const VarDecl *VD = getArgVarDecl(Arg)) {
      const bool *Owned = State->get<OwnedVars>(VD);
      if (Owned && *Owned) {
        State = State->set<OwnedVars>(VD, false);
        Changed = true;
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  llvm::SmallVector<const Expr *, 4> NonNull;
  collectNonNullTests(CondE, NonNull, C.getASTContext());

  ProgramStateRef State = C.getState();
  const VarDecl *Res = nullptr;

  for (const Expr *E : NonNull) {
    if (const VarDecl *VD = getArgVarDecl(E)) {
      const bool *Owned = State->get<OwnedVars>(VD);
      if (Owned && *Owned) {
        Res = VD;
        break;
      }
    }
  }

  if (!Res)
    return;

  // A guarded transfer needs at least the resource guard and the container guard.
  if (NonNull.size() < 2)
    return;

  if (!thenTransfers(IS->getThen(), Res, C))
    return;

  if (elseDeallocates(IS->getElse(), Res, C))
    return;

  reportLeak(IS, Res, C);
}

void SAGenTestChecker::reportLeak(const IfStmt *IS, const VarDecl *Res,
                                  CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential resource leak: missing deallocation when transfer is skipped",
      N);

  Report->addRange(IS->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects resource leaks when a guarded ownership transfer is skipped",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "duplicator": {"names": ["sqlite3SrcListDup"], "description": "returns a newly allocated copy of an object; caller owns the copy and must free it"},
  "container_insert": {"names": ["sqlite3SrcListAppendList", "sqlite3SrcListAppendFromTerm"], "description": "attaches or appends an owned resource to a container; the passed resource is consumed, and any returned container is owned by the caller"},
  "deallocator": {"names": ["sqlite3SrcListDelete"], "description": "frees an object or container; safe to call with NULL"},
  "null_on_failure": {"names": ["sqlite3SrcListDup", "sqlite3SrcListAppendList"], "description": "may return NULL on allocation failure"}
}
*/
