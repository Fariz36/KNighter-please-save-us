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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/APSInt.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(CheckedNullPtrFields, const MemRegion *)

namespace {

static bool sameExpr(const Expr *A, const Expr *B) {
  if (!A || !B)
    return false;

  A = A->IgnoreParenImpCasts();
  B = B->IgnoreParenImpCasts();

  if (A == B)
    return true;

  if (const DeclRefExpr *DREA = dyn_cast<DeclRefExpr>(A)) {
    if (const DeclRefExpr *DREB = dyn_cast<DeclRefExpr>(B))
      return DREA->getDecl() == DREB->getDecl();
  }

  if (const MemberExpr *MEA = dyn_cast<MemberExpr>(A)) {
    if (const MemberExpr *MEB = dyn_cast<MemberExpr>(B))
      return MEA->getMemberDecl() == MEB->getMemberDecl() &&
             sameExpr(MEA->getBase(), MEB->getBase());
  }

  return false;
}

static const MemRegion *getFieldRegion(const MemberExpr *ME,
                                       CheckerContext &C,
                                       ProgramStateRef State) {
  if (!ME)
    return nullptr;

  const Expr *Base = ME->getBase();
  if (!Base)
    return nullptr;

  SVal BaseVal = State->getSVal(Base, C.getLocationContext());
  const MemRegion *BaseMR = BaseVal.getAsRegion();
  if (!BaseMR)
    return nullptr;

  const SubRegion *BaseSR = dyn_cast<SubRegion>(BaseMR);
  if (!BaseSR)
    return nullptr;

  const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD)
    return nullptr;

  return State->getStateManager().getRegionManager().getFieldRegion(FD, BaseSR);
}

class SAGenTestChecker
    : public Checker<check::PreCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "NULL Pointer", "Dereference")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  ProgramStateRef markFieldChecked(const MemberExpr *ME, CheckerContext &C,
                                   ProgramStateRef State) const;
  ProgramStateRef markNullCheckedFields(const Expr *E, CheckerContext &C,
                                        ProgramStateRef State) const;
};

ProgramStateRef SAGenTestChecker::markFieldChecked(const MemberExpr *ME,
                                                   CheckerContext &C,
                                                   ProgramStateRef State) const {
  const MemRegion *MR = getFieldRegion(ME, C, State);
  if (!MR)
    return State;

  return State->add<CheckedNullPtrFields>(MR);
}

ProgramStateRef SAGenTestChecker::markNullCheckedFields(const Expr *E,
                                                        CheckerContext &C,
                                                        ProgramStateRef State) const {
  if (!E)
    return State;

  E = E->IgnoreParenImpCasts();
  if (!E)
    return State;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd || BO->getOpcode() == BO_LOr) {
      State = markNullCheckedFields(BO->getLHS(), C, State);
      State = markNullCheckedFields(BO->getRHS(), C, State);
      return State;
    }

    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSIsNull = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);

      const Expr *PtrExpr = nullptr;
      if (LHSIsNull && !RHSIsNull)
        PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrExpr = LHS;

      if (PtrExpr) {
        const Expr *Sub = PtrExpr->IgnoreParenImpCasts();
        if (const MemberExpr *ME = dyn_cast<MemberExpr>(Sub)) {
          if (ME->getType()->isPointerType())
            State = markFieldChecked(ME, C, State);
        }
      }
      return State;
    }
  }

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const MemberExpr *ME = dyn_cast<MemberExpr>(Sub)) {
        if (ME->getType()->isPointerType())
          State = markFieldChecked(ME, C, State);
      }
    }
    return State;
  }

  if (const MemberExpr *ME = dyn_cast<MemberExpr>(E)) {
    if (ME->getType()->isPointerType())
      State = markFieldChecked(ME, C, State);
  }

  return State;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  ProgramStateRef State = C.getState();
  ProgramStateRef NewState = markNullCheckedFields(Cond, C, State);
  if (NewState != State)
    C.addTransition(NewState);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "buffer_copy"))
    return;

  if (Call.getNumArgs() < 3)
    return;

  const Expr *SrcArg = Call.getArgExpr(1);
  const Expr *SizeArg = Call.getArgExpr(2);
  if (!SrcArg || !SizeArg)
    return;

  const Expr *Src = SrcArg->IgnoreParenImpCasts();
  const Expr *Size = SizeArg->IgnoreParenImpCasts();

  const MemberExpr *SrcME = dyn_cast<MemberExpr>(Src);
  const MemberExpr *SizeME = dyn_cast<MemberExpr>(Size);
  if (!SrcME || !SizeME)
    return;

  if (!SrcME->getType()->isPointerType())
    return;

  if (!SizeME->getType()->isIntegerType())
    return;

  const Expr *SrcBase = SrcME->getBase()->IgnoreParenImpCasts();
  const Expr *SizeBase = SizeME->getBase()->IgnoreParenImpCasts();
  if (!sameExpr(SrcBase, SizeBase))
    return;

  ProgramStateRef State = C.getState();

  const MemRegion *SrcMR = getFieldRegion(SrcME, C, State);
  if (!SrcMR)
    return;

  if (State->contains<CheckedNullPtrFields>(SrcMR))
    return;

  SVal SizeVal = State->getSVal(SizeME, C.getLocationContext());
  SymbolRef SizeSym = SizeVal.getAsSymbol();
  if (!SizeSym)
    return;

  const llvm::APSInt *MinVal =
      State->getConstraintManager().getSymMinVal(State, SizeSym);
  if (!MinVal || MinVal->isNegative() || MinVal->isZero())
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Buffer copy from a possibly NULL pointer field; length is nonzero and "
      "pointer was not NULL-checked",
      N);
  Report->addRange(SrcArg->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects buffer copies from unchecked NULL pointer fields",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "buffer_copy": {"names": ["memcpy"], "description": "copies a number of bytes from a source pointer to a destination pointer; the source pointer must be valid if the size is nonzero"},
  "allocator": {"names": ["curlx_malloc"], "description": "allocates memory and may return NULL on failure"},
  "null_on_failure": {"names": ["curlx_malloc"], "description": "allocation function that returns NULL on failure"},
  "deallocator": {"names": ["curlx_safefree"], "description": "frees memory previously allocated; pointer must not be used after"}
}
*/
