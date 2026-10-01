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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Marks pointer variables that were directly assigned from a strchr() call.
REGISTER_MAP_WITH_PROGRAMSTATE(StrchrPtrMap, const MemRegion *, bool)
// Marks pointers that may point to a NUL terminator after being incremented.
// false = unchecked, true = checked.
REGISTER_MAP_WITH_PROGRAMSTATE(NulPtrMap, const MemRegion *, bool)
// Maps a 'sep' variable region to the NUL-vulnerable pointer region it was
// assigned from (i.e. sep = ptr[0]).
REGISTER_MAP_WITH_PROGRAMSTATE(SepMap, const MemRegion *, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<
    check::PostStmt<DeclStmt>,
    check::Bind,
    check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read",
                       "Memory safety")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                 CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  bool isStrchrCall(const Expr *E, CheckerContext &C) const;
  const MemRegion *getPointerVariableRegion(const Expr *E,
                                            CheckerContext &C) const;
  void checkConditionExpr(const Expr *E, CheckerContext &C,
                          ProgramStateRef &State) const;
  void markCheckedFromExpr(const Expr *E, CheckerContext &C,
                           ProgramStateRef &State) const;
  void reportOOB(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isStrchrCall(const Expr *E,
                                    CheckerContext &C) const {
  if (!E)
    return false;
  const Expr *CE = E->IgnoreParenImpCasts();
  if (isa<CallExpr>(CE))
    return ExprHasName(CE, "strchr", C);
  return false;
}

const MemRegion *SAGenTestChecker::getPointerVariableRegion(
    const Expr *E, CheckerContext &C) const {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      const VarRegion *VR = C.getState()->getRegion(VD, C.getLocationContext());
      if (VR)
        return VR->getBaseRegion();
    }
  }
  return nullptr;
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  for (const Decl *D : DS->decls()) {
    const VarDecl *VD = dyn_cast<VarDecl>(D);
    if (!VD || !VD->hasInit())
      continue;
    const Expr *Init = VD->getInit();
    if (isStrchrCall(Init, C)) {
      const VarRegion *VR = State->getRegion(VD, C.getLocationContext());
      if (VR) {
        State = State->set<StrchrPtrMap>(VR->getBaseRegion(), true);
      }
    }
  }
  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (!StoreE)
    return;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(StoreE)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *RHS = BO->getRHS();

      // Track: ptr = strchr(...)
      if (isStrchrCall(RHS, C)) {
        if (const MemRegion *LHSReg = Loc.getAsRegion()) {
          LHSReg = LHSReg->getBaseRegion();
          State = State->set<StrchrPtrMap>(LHSReg, true);
        }
      }

      // Track: sep = ptr[0]
      const Expr *RHSC = RHS->IgnoreParenImpCasts();
      if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(RHSC)) {
        llvm::APSInt Idx;
        if (EvaluateExprToInt(Idx, ASE->getIdx(), C) && Idx == 0) {
          const MemRegion *BaseVarReg =
              getPointerVariableRegion(ASE->getBase(), C);
          if (BaseVarReg) {
            const bool *Unchecked = State->get<NulPtrMap>(BaseVarReg);
            if (Unchecked && *Unchecked == false) {
              if (const MemRegion *LHSReg = Loc.getAsRegion()) {
                LHSReg = LHSReg->getBaseRegion();
                State = State->set<SepMap>(LHSReg, BaseVarReg);
              }
            }
          }
        }
      }
    }
  } else if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(StoreE)) {
    if (UO->isIncrementDecrementOp()) {
      const MemRegion *OperandReg =
          getPointerVariableRegion(UO->getSubExpr(), C);
      if (OperandReg) {
        const bool *IsStrchr = State->get<StrchrPtrMap>(OperandReg);
        if (IsStrchr && *IsStrchr) {
          State = State->set<NulPtrMap>(OperandReg, false);
        }
      }
    }
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();
  checkConditionExpr(CondE, C, State);
  // State is only used for local short-circuit reasoning; we do not persist it.
}

void SAGenTestChecker::checkConditionExpr(const Expr *E, CheckerContext &C,
                                          ProgramStateRef &State) const {
  if (!E)
    return;
  E = E->IgnoreParenImpCasts();

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      checkConditionExpr(BO->getLHS(), C, State);
      markCheckedFromExpr(BO->getLHS(), C, State);
      checkConditionExpr(BO->getRHS(), C, State);
      return;
    }
    checkConditionExpr(BO->getLHS(), C, State);
    checkConditionExpr(BO->getRHS(), C, State);
    return;
  }

  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    llvm::APSInt Idx;
    if (EvaluateExprToInt(Idx, ASE->getIdx(), C) && Idx > 0) {
      const MemRegion *BaseReg =
          getPointerVariableRegion(ASE->getBase(), C);
      if (BaseReg) {
        const bool *Unchecked = State->get<NulPtrMap>(BaseReg);
        if (Unchecked && *Unchecked == false) {
          reportOOB(ASE, C);
          // Suppress further reports for this pointer in this condition.
          State = State->set<NulPtrMap>(BaseReg, true);
        }
      }
    }
    return;
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child))
      checkConditionExpr(ChildE, C, State);
  }
}

void SAGenTestChecker::markCheckedFromExpr(const Expr *E, CheckerContext &C,
                                           ProgramStateRef &State) const {
  if (!E)
    return;
  E = E->IgnoreParenImpCasts();

  // If it's a variable (e.g., sep), check SepMap.
  const MemRegion *VarReg = getPointerVariableRegion(E, C);
  if (VarReg) {
    if (const MemRegion *const *PtrRegPtr = State->get<SepMap>(VarReg)) {
      const MemRegion *PtrReg = *PtrRegPtr;
      if (PtrReg) {
        State = State->set<NulPtrMap>(PtrReg, true);
      }
    }
  }

  // If it's ptr[0], mark the base pointer as checked.
  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    llvm::APSInt Idx;
    if (EvaluateExprToInt(Idx, ASE->getIdx(), C) && Idx == 0) {
      const MemRegion *BaseReg =
          getPointerVariableRegion(ASE->getBase(), C);
      if (BaseReg) {
        const bool *Unchecked = State->get<NulPtrMap>(BaseReg);
        if (Unchecked) {
          State = State->set<NulPtrMap>(BaseReg, true);
        }
      }
    }
  }
}

void SAGenTestChecker::reportOOB(const ArraySubscriptExpr *ASE,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Out-of-bounds read: pointer may point to NUL terminator", N);
  Report->addRange(ASE->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects out-of-bounds reads after incrementing strchr result without NUL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
