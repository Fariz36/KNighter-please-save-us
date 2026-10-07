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

REGISTER_MAP_WITH_PROGRAMSTATE(CheckedPtrMap, SymbolRef, bool)

namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "NULL Pointer Dereference", "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void markCheckedInCondition(const Expr *Cond, CheckerContext &C,
                              ProgramStateRef &State) const;
};

} // end anonymous namespace

// Helper: extract the pointer expression being tested for NULL, if any.
static const Expr *getNullCheckedExpr(const Expr *Cond, CheckerContext &C) {
  if (!Cond)
    return nullptr;
  Cond = Cond->IgnoreParenCasts();
  ASTContext &AC = C.getASTContext();

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
      if (Sub->getType()->isPointerType())
        return Sub;
    }
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHSIsNull =
          LHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull =
          RHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && !RHSIsNull && RHS->getType()->isPointerType())
        return RHS;
      if (RHSIsNull && !LHSIsNull && LHS->getType()->isPointerType())
        return LHS;
    }
  } else {
    if (Cond->getType()->isPointerType())
      return Cond;
  }
  return nullptr;
}

// Helper: true if E is a member access on a pointer parameter (input struct).
static bool isInputStructMember(const Expr *E, CheckerContext &C,
                                const ParmVarDecl *&BaseParm) {
  if (!E)
    return false;
  E = E->IgnoreParenCasts();
  const MemberExpr *ME = dyn_cast<MemberExpr>(E);
  if (!ME)
    return false;
  const Expr *Base = ME->getBase()->IgnoreParenCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base);
  if (!DRE)
    return false;
  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD)
    return false;
  if (!PVD->getType()->isPointerType())
    return false;
  BaseParm = PVD;
  return true;
}

// Helper: obtain the symbolic value of an expression.
static SymbolRef getSymbolFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  SVal V = C.getState()->getSVal(E, C.getLocationContext());
  return V.getAsSymbol();
}

void SAGenTestChecker::markCheckedInCondition(const Expr *Cond,
                                              CheckerContext &C,
                                              ProgramStateRef &State) const {
  if (!Cond)
    return;
  Cond = Cond->IgnoreParenCasts();

  // If the condition itself is a NULL-check on a pointer, mark that pointer.
  const Expr *PtrExpr = getNullCheckedExpr(Cond, C);
  if (PtrExpr) {
    const ParmVarDecl *BaseParm = nullptr;
    if (isInputStructMember(PtrExpr, C, BaseParm)) {
      SymbolRef Sym = getSymbolFromExpr(PtrExpr, C);
      if (Sym) {
        State = State->set<CheckedPtrMap>(Sym, true);
      }
    }
  }

  // Recurse into logical `||` and `&&` to find NULL-checks in subexpressions.
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_LOr || BO->getOpcode() == BO_LAnd) {
      markCheckedInCondition(BO->getLHS(), C, State);
      markCheckedInCondition(BO->getRHS(), C, State);
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;
  ProgramStateRef State = C.getState();
  markCheckedInCondition(CondE, C, State);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "buffer_copy"))
    return;

  if (Call.getNumArgs() < 2)
    return;
  const Expr *Src = Call.getArgExpr(1);
  if (!Src)
    return;

  const ParmVarDecl *BaseParm = nullptr;
  if (!isInputStructMember(Src, C, BaseParm))
    return;

  SymbolRef Sym = getSymbolFromExpr(Src, C);
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<CheckedPtrMap>(Sym);
  if (Checked && *Checked)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Payload pointer may be NULL before buffer copy", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereference of a caller-supplied input struct's payload pointer "
      "without prior NULL check before a buffer copy",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {"names": ["curlx_malloc"], "description": "allocates memory and may return NULL on failure"},
  "deallocator": {"names": ["curlx_safefree"], "description": "frees memory or an object; the pointer must not be used afterwards"},
  "buffer_copy": {"names": ["memcpy"], "description": "copies bytes from a source buffer to a destination buffer; the source must be valid for the given length"},
  "null_on_failure": {"names": ["curlx_malloc"], "description": "function that may return NULL on failure, so its result must be checked before use"}
}
*/
