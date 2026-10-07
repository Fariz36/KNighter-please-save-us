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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(GuardedParams, const MemRegion *)

namespace {

static const ParmVarDecl *getDerefParam(const Expr *E, const DeclRefExpr *&DRE) {
  DRE = nullptr;
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *D = dyn_cast<DeclRefExpr>(Sub)) {
        if (const auto *P = dyn_cast<ParmVarDecl>(D->getDecl())) {
          if (P->getType()->isPointerType()) {
            DRE = D;
            return P;
          }
        }
      }
    }
  }

  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
    if (const auto *D = dyn_cast<DeclRefExpr>(Base)) {
      if (const auto *P = dyn_cast<ParmVarDecl>(D->getDecl())) {
        if (P->getType()->isPointerType()) {
          DRE = D;
          return P;
        }
      }
    }
  }

  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (ME->isArrow()) {
      const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
      if (const auto *D = dyn_cast<DeclRefExpr>(Base)) {
        if (const auto *P = dyn_cast<ParmVarDecl>(D->getDecl())) {
          if (P->getType()->isPointerType()) {
            DRE = D;
            return P;
          }
        }
      }
    }
  }

  return nullptr;
}

static const ParmVarDecl *getParamFromNullCheck(const Expr *Cond,
                                                bool &isNullCheck,
                                                const DeclRefExpr *&DRE,
                                                ASTContext &Ctx) {
  isNullCheck = false;
  DRE = nullptr;
  if (!Cond)
    return nullptr;
  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *D = dyn_cast<DeclRefExpr>(Sub)) {
        if (const auto *P = dyn_cast<ParmVarDecl>(D->getDecl())) {
          if (P->getType()->isPointerType()) {
            isNullCheck = true;
            DRE = D;
            return P;
          }
        }
      }
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      auto isNull = [&](const Expr *E) {
        return E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
      };
      const Expr *PtrExpr = nullptr;
      if (isNull(RHS))
        PtrExpr = LHS;
      else if (isNull(LHS))
        PtrExpr = RHS;

      if (PtrExpr) {
        if (const auto *D = dyn_cast<DeclRefExpr>(PtrExpr)) {
          if (const auto *P = dyn_cast<ParmVarDecl>(D->getDecl())) {
            if (P->getType()->isPointerType()) {
              // For ==, condition true means the pointer is NULL.
              // For !=, condition true means the pointer is non-NULL.
              isNullCheck = (BO->getOpcode() == BO_EQ);
              DRE = D;
              return P;
            }
          }
        }
      }
    }
  }

  return nullptr;
}

static bool thenBranchReturns(const IfStmt *IS) {
  if (!IS)
    return false;
  const Stmt *Then = IS->getThen();
  if (!Then)
    return false;
  if (isa<ReturnStmt>(Then))
    return true;
  if (const auto *CS = dyn_cast<CompoundStmt>(Then)) {
    for (const Stmt *S : CS->body()) {
      if (isa<ReturnStmt>(S))
        return true;
    }
  }
  return false;
}

class SAGenTestChecker
    : public Checker<check::PreCall,
                     check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Pointer parameter dereferenced before NULL check",
                       "Null Pointer Dereference")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  bool isNullCheck = false;
  const DeclRefExpr *DRE = nullptr;
  const ParmVarDecl *P =
      getParamFromNullCheck(CondE, isNullCheck, DRE, C.getASTContext());
  if (!P || !isNullCheck || !thenBranchReturns(IS))
    return;

  if (!DRE)
    return;

  ProgramStateRef State = C.getState();
  SVal SV = State->getSVal(DRE, C.getLocationContext());
  const MemRegion *R = SV.getAsRegion();
  if (!R)
    return;
  R = R->getBaseRegion();
  if (!R)
    return;

  State = State->add<GuardedParams>(R);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "capacity_calculator"))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *Arg = Call.getArgExpr(i);
    if (!Arg)
      continue;

    const DeclRefExpr *DRE = nullptr;
    const ParmVarDecl *P = getDerefParam(Arg, DRE);
    if (!P || !DRE)
      continue;

    SVal SV = State->getSVal(DRE, C.getLocationContext());
    const MemRegion *R = SV.getAsRegion();
    if (!R)
      continue;
    R = R->getBaseRegion();
    if (!R)
      continue;

    if (!State->contains<GuardedParams>(R)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Pointer parameter dereferenced before NULL check", N);
      report->addRange(Arg->getSourceRange());
      C.emitReport(std::move(report));
      break;
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of a pointer parameter before a NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "capacity_calculator": {
    "names": ["xmlGrowCapacity"],
    "description": "computes a new capacity/size from a current capacity value, element size, and bounds"
  },
  "reallocator": {
    "names": ["xmlRealloc"],
    "description": "resizes an allocation and may return NULL on failure"
  }
}
*/
