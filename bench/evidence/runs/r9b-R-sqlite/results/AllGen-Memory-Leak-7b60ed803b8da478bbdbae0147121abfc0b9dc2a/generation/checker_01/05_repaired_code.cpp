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
#include "clang/AST/ParentMap.h"
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "knighter/roles.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(OwnedPtrMap, const MemRegion *, bool)

namespace {

static bool isAssignedToLocalVariable(const Expr *E, CheckerContext &C) {
  if (!E) return false;

  // Check if E is the initializer of a local VarDecl.
  ASTContext &Ctx = C.getASTContext();
  bool isInitializer = false;
  bool isLocalInitializer = false;
  for (const auto &Parent : Ctx.getParents(DynTypedNode::create(*E))) {
    if (const auto *VD = Parent.get<VarDecl>()) {
      if (VD->getInit() &&
          VD->getInit()->IgnoreParenCasts() == E->IgnoreParenCasts()) {
        isInitializer = true;
        isLocalInitializer = VD->isLocalVarDecl();
        break;
      }
    }
  }
  if (isInitializer)
    return isLocalInitializer;

  // Check if E is the RHS of an assignment to a local variable.
  const ParentMap &PM = C.getCurrentAnalysisDeclContext()->getParentMap();
  if (const auto *BO = dyn_cast_or_null<BinaryOperator>(PM.getParent(E))) {
    if (BO->getOpcode() == BO_Assign &&
        BO->getRHS()->IgnoreParenCasts() == E->IgnoreParenCasts()) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          return VD->isLocalVarDecl();
        }
      }
    }
  }
  return false;
}

static const Expr *getPointerFromNonNullCheck(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  E = E->IgnoreParenCasts();
  if (E->getType()->isPointerType()) {
    return E;
  }
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && !RHSIsNull && RHS->getType()->isPointerType())
        return RHS;
      if (RHSIsNull && !LHSIsNull && LHS->getType()->isPointerType())
        return LHS;
    }
  }
  return nullptr;
}

static bool callHasArgMatchingRegion(const CallExpr *CE,
                                     const MemRegion *SourceReg,
                                     CheckerContext &C) {
  if (!CE || !SourceReg) return false;
  ProgramStateRef State = C.getState();
  for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
    const Expr *Arg = CE->getArg(i);
    SVal ArgVal = State->getSVal(Arg, C.getLocationContext());
    if (const MemRegion *MR = ArgVal.getAsRegion()) {
      MR = MR->getBaseRegion();
      if (MR == SourceReg) return true;
    }
  }
  return false;
}

static bool branchContainsRoleCallWithRegion(const Stmt *S,
                                             const char *Role,
                                             const MemRegion *SourceReg,
                                             CheckerContext &C) {
  if (!S) return false;
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (knighter::callExprIsRole(CE, Role, C.getASTContext())) {
      if (callHasArgMatchingRegion(CE, SourceReg, C)) return true;
    }
  }
  for (const Stmt *Child : S->children()) {
    if (branchContainsRoleCallWithRegion(Child, Role, SourceReg, C)) return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory Leak", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportLeak(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "duplicator") &&
      !knighter::callIsRole(Call, "null_on_failure"))
    return;

  const Expr *CE = Call.getOriginExpr();
  if (!CE) return;
  if (!isAssignedToLocalVariable(CE, C)) return;

  const MemRegion *MR = Call.getReturnValue().getAsRegion();
  if (!MR) return;
  MR = MR->getBaseRegion();
  if (!MR) return;

  ProgramStateRef State = C.getState();
  State = State->set<OwnedPtrMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  bool isDealloc = knighter::callIsRole(Call, "deallocator");
  bool isInsert = knighter::callIsRole(Call, "container_insert");
  if (!isDealloc && !isInsert) return;

  ProgramStateRef State = C.getState();
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    SVal Arg = Call.getArgSVal(i);
    const MemRegion *MR = Arg.getAsRegion();
    if (!MR) continue;
    MR = MR->getBaseRegion();
    if (!MR) continue;
    if (State->get<OwnedPtrMap>(MR)) {
      State = State->remove<OwnedPtrMap>(MR);
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond) return;
  Cond = Cond->IgnoreParenCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO || BO->getOpcode() != BO_LAnd) return;

  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

  const Expr *PtrLHS = getPointerFromNonNullCheck(LHS, C);
  const Expr *PtrRHS = getPointerFromNonNullCheck(RHS, C);
  if (!PtrLHS || !PtrRHS) return;

  ProgramStateRef State = C.getState();
  const MemRegion *OwnedReg = nullptr;

  // Check LHS for an owned pointer.
  if (const auto *DRE = dyn_cast<DeclRefExpr>(PtrLHS)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (VD->isLocalVarDecl()) {
        SVal Val = State->getSVal(PtrLHS, C.getLocationContext());
        if (const MemRegion *MR = Val.getAsRegion()) {
          MR = MR->getBaseRegion();
          if (MR && State->get<OwnedPtrMap>(MR)) {
            OwnedReg = MR;
          }
        }
      }
    }
  }

  // If LHS is not owned, check RHS.
  if (!OwnedReg) {
    if (const auto *DRE = dyn_cast<DeclRefExpr>(PtrRHS)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (VD->isLocalVarDecl()) {
          SVal Val = State->getSVal(PtrRHS, C.getLocationContext());
          if (const MemRegion *MR = Val.getAsRegion()) {
            MR = MR->getBaseRegion();
            if (MR && State->get<OwnedPtrMap>(MR)) {
              OwnedReg = MR;
            }
          }
        }
      }
    }
  }

  if (!OwnedReg) return;

  const IfStmt *If = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!If) return;

  const Stmt *Then = If->getThen();
  const Stmt *Else = If->getElse();
  if (!Then) return;

  bool hasInsert =
      branchContainsRoleCallWithRegion(Then, "container_insert", OwnedReg, C);
  if (!hasInsert) return;

  bool hasDealloc = false;
  if (Else) {
    hasDealloc =
        branchContainsRoleCallWithRegion(Else, "deallocator", OwnedReg, C);
  }

  if (!hasDealloc) {
    reportLeak(Condition, C);
  }
}

void SAGenTestChecker::reportLeak(const Stmt *Condition,
                                  CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Memory leak: resource not deallocated on skipped transfer branch.",
      N);
  Report->addRange(Condition->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memory leaks when a resource transfer is skipped due to a NULL "
      "destination without deallocating the source.",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "duplicator": {"names": ["sqlite3SrcListDup"], "description": "creates a new copy of an object; returns a pointer that must be freed by the caller"},
  "deallocator": {"names": ["sqlite3SrcListDelete"], "description": "frees an object; the pointer must not be used afterwards"},
  "container_insert": {"names": ["sqlite3SrcListAppendList"], "description": "appends an element to a container and takes ownership of the element"},
  "null_on_failure": {"names": ["triggerStepAllocate", "sqlite3SrcListDup", "sqlite3SelectNew", "sqlite3SrcListAppendFromTerm", "sqlite3SrcListAppendList"], "description": "may return NULL on allocation failure"}
}
*/
