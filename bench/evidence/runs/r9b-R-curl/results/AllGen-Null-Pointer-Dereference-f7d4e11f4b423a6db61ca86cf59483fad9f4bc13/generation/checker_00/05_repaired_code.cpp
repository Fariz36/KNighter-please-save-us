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
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_TRAIT_WITH_PROGRAMSTATE(SawAllocator, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(CheckedPtrMap, SymbolRef, bool)

namespace {

class SAGenTestChecker : public Checker<check::BeginFunction,
                                        check::PostCall,
                                        check::BranchCondition,
                                        check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Null pointer dereference", "Null pointer")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportMissingNullCheck(const CallEvent &Call, const Expr *SrcExpr,
                              CheckerContext &C) const;
};

} // end anonymous namespace

static bool originatesFromParam(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return isa<ParmVarDecl>(DRE->getDecl());
  }
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    return originatesFromParam(ME->getBase());
  }
  return false;
}

static void markChecked(ProgramStateRef &State, const Expr *E,
                        CheckerContext &C) {
  if (!E)
    return;
  E = E->IgnoreParenImpCasts();
  if (!E->getType()->isPointerType())
    return;

  SVal V = State->getSVal(E, C.getLocationContext());
  if (SymbolRef Sym = V.getAsSymbol()) {
    State = State->set<CheckedPtrMap>(Sym, true);
  }
}

static void findNullChecks(const Expr *E, ProgramStateRef &State,
                           CheckerContext &C) {
  if (!E)
    return;
  E = E->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      markChecked(State, UO->getSubExpr(), C);
      return;
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_LOr || Op == BO_LAnd) {
      findNullChecks(BO->getLHS(), State, C);
      findNullChecks(BO->getRHS(), State, C);
      return;
    }
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LNull = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RNull = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      if (LNull && !RNull) {
        markChecked(State, RHS, C);
      } else if (RNull && !LNull) {
        markChecked(State, LHS, C);
      }
      return;
    }
  }

  // Implicit comparison to zero, e.g. if (ptr)
  markChecked(State, E, C);
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  State = State->set<SawAllocator>(false);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "allocator"))
    return;

  ProgramStateRef State = C.getState();
  State = State->set<SawAllocator>(true);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                           CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  ProgramStateRef State = C.getState();
  findNullChecks(Cond, State, C);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "buffer_copy"))
    return;

  ProgramStateRef State = C.getState();
  bool Saw = State->get<SawAllocator>();
  if (!Saw)
    return;

  if (Call.getNumArgs() <= 1)
    return;

  const Expr *SrcExpr = Call.getArgExpr(1);
  if (!SrcExpr)
    return;

  if (!originatesFromParam(SrcExpr))
    return;

  SVal SrcVal = Call.getArgSVal(1);
  SymbolRef Sym = SrcVal.getAsSymbol();
  if (!Sym)
    return;

  const bool *Checked = State->get<CheckedPtrMap>(Sym);
  if (Checked && *Checked)
    return;

  reportMissingNullCheck(Call, SrcExpr, C);
}

void SAGenTestChecker::reportMissingNullCheck(const CallEvent &Call,
                                             const Expr *SrcExpr,
                                             CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Buffer source pointer is not validated for NULL before being copied.",
      N);
  Report->addRange(SrcExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL validation of buffer source pointers before a "
      "buffer_copy",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {"names": ["curlx_malloc"], "description": "allocates memory and may return NULL on failure"},
  "deallocator": {"names": ["curlx_safefree"], "description": "releases memory or an object; the pointer must not be used afterwards"},
  "buffer_copy": {"names": ["memcpy"], "description": "copies data from a source pointer to a destination pointer; the source pointer must be valid"}
}
*/
