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
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map to track unchecked pointer parameters.
// Key: the base MemRegion that the pointer points to.
// Value: true if not yet NULL-checked, false if already checked.
REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedPtrMap, const MemRegion *, bool)

namespace {
class SAGenTestChecker : public Checker<check::BeginFunction,
                                        check::BranchCondition,
                                        check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Dereferencing pointer parameter without NULL check",
                       "Null Pointer Dereference")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool isLoad, const Stmt *S, CheckerContext &C) const;

private:
  const MemRegion *getCheckedRegion(const Expr *Cond, CheckerContext &C) const;
  void reportNullDeref(const Stmt *S, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const Decl *D = C.getCurrentAnalysisDeclContext()->getDecl();
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  // Optionally skip static functions to focus on public APIs.
  if (FD->isStatic())
    return;

  ProgramStateRef State = C.getState();
  for (const ParmVarDecl *P : FD->parameters()) {
    QualType QT = P->getType();
    if (!QT->isPointerType())
      continue;

    const MemRegion *ParamR = C.getState()->getLValue(P, C.getLocationContext()).getAsRegion();
    SVal V = State->getSVal(ParamR);
    if (const MemRegion *R = V.getAsRegion()) {
      R = R->getBaseRegion();
      State = State->set<UncheckedPtrMap>(R, true);
    }
  }
  C.addTransition(State);
}

const MemRegion *SAGenTestChecker::getCheckedRegion(const Expr *Cond,
                                                    CheckerContext &C) const {
  if (!Cond)
    return nullptr;

  Cond = Cond->IgnoreParenImpCasts();

  // Pattern: !ptr
  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      SVal V = C.getState()->getSVal(Sub, C.getLocationContext());
      return V.getAsRegion();
    }
  }

  // Pattern: ptr == NULL, ptr != NULL, ptr == 0, ptr != 0
  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      ASTContext &AC = C.getASTContext();
      bool LHSIsNull =
          LHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull =
          RHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);
      const Expr *PtrExpr = nullptr;
      if (LHSIsNull && !RHSIsNull)
        PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrExpr = LHS;
      if (PtrExpr) {
        SVal V = C.getState()->getSVal(PtrExpr, C.getLocationContext());
        return V.getAsRegion();
      }
    }
  }

  // Pattern: ptr (implicit non-null check)
  SVal V = C.getState()->getSVal(Cond, C.getLocationContext());
  return V.getAsRegion();
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  const MemRegion *R = getCheckedRegion(Cond, C);
  if (!R)
    return;

  R = R->getBaseRegion();
  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<UncheckedPtrMap>(R);
  if (Checked && *Checked) {
    State = State->set<UncheckedPtrMap>(R, false);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool isLoad, const Stmt *S,
                                     CheckerContext &C) const {
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;
  R = R->getBaseRegion();

  ProgramStateRef State = C.getState();
  const bool *Unchecked = State->get<UncheckedPtrMap>(R);
  if (Unchecked && *Unchecked) {
    reportNullDeref(S, C);
  }
}

void SAGenTestChecker::reportNullDeref(const Stmt *S,
                                       CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Dereferencing pointer parameter without NULL check", N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereferences of pointer parameters without prior NULL checks",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
