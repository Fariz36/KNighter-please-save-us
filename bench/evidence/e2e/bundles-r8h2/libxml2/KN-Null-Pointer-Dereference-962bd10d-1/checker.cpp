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
#include "llvm/Support/Casting.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(GuardedCapacityMap, const ParmVarDecl *, bool)

namespace {

class SAGenTestChecker
    : public Checker<check::BranchCondition, check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Null pointer dereference",
                       "Null Pointer Dereference")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
};

} // end anonymous namespace

static const ParmVarDecl *findRoleParamInCondition(const Stmt *Cond) {
  if (!Cond)
    return nullptr;

  if (const Expr *E = dyn_cast<Expr>(Cond)) {
    E = E->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const auto *P = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
        if (knighter::declIsRole(P, "nullable_inout_capacity_ptr"))
          return P;
      }
    }
  }

  for (const Stmt *Child : Cond->children()) {
    if (const ParmVarDecl *P = findRoleParamInCondition(Child))
      return P;
  }

  return nullptr;
}

static const ParmVarDecl *getDerefRoleParam(const Stmt *S) {
  if (!S)
    return nullptr;

  if (const Expr *E = dyn_cast<Expr>(S)) {
    E = E->IgnoreParenImpCasts();
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_Deref) {
        const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
        if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
          if (const auto *P = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
            if (knighter::declIsRole(P, "nullable_inout_capacity_ptr"))
              return P;
          }
        }
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (const ParmVarDecl *P = getDerefRoleParam(Child))
      return P;
  }

  return nullptr;
}

namespace {

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const ParmVarDecl *P = findRoleParamInCondition(Condition);
  if (!P)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<GuardedCapacityMap>(P, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  const ParmVarDecl *P = getDerefRoleParam(S);
  if (!P)
    return;

  ProgramStateRef State = C.getState();
  if (const bool *Guarded = State->get<GuardedCapacityMap>(P)) {
    if (*Guarded)
      return;
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "in/out capacity pointer dereferenced without null check", N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of an in/out capacity pointer without a preceding "
      "NULL guard",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "nullable_inout_capacity_ptr": {"names": ["capacity"], "description": "pointer parameter used as an in/out capacity slot; must be null-checked before dereference"},
  "capacity_computer": {"names": ["xmlGrowCapacity"], "description": "function that computes a new capacity from the current capacity value"},
  "reallocator": {"names": ["xmlRealloc"], "description": "memory reallocation function"},
  "deref_read": {"names": [], "description": "read through the capacity pointer, e.g., *capacity"},
  "deref_write": {"names": [], "description": "write through the capacity pointer, e.g., *capacity = newSize"},
  "null_guard": {"names": [], "description": "early-return null check, e.g., if (capacity == NULL) return NULL;"},
  "null_on_failure": {"names": [], "description": "condition indicating failure, e.g., realloc returning NULL or capacity computer returning negative"}
}
*/
