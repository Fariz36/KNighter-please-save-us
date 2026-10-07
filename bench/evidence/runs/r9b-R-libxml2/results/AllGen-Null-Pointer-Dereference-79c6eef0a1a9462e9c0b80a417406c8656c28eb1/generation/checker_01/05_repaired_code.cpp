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

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks symbols returned by duplicator / null_on_failure calls that have not
// yet been NULL-checked.
REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedDupMap, SymbolRef, bool)

namespace {

static SymbolRef getSymbolFromSVal(SVal V) {
  if (SymbolRef Sym = V.getAsLocSymbol())
    return Sym;
  return V.getAsSymbol();
}

static bool isNullConstant(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  if (isa<GNUNullExpr>(E))
    return true;

  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, E, C) && Val == 0)
    return true;

  return E->isNullPointerConstant(C.getASTContext(),
                                  Expr::NPC_ValueDependentIsNull);
}

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked duplicator result", "Memory error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "duplicator") &&
      !knighter::callIsRole(Call, "null_on_failure"))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = getSymbolFromSVal(RetVal);
  if (!Sym)
    return;

  State = State->set<UncheckedDupMap>(Sym, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "length_of"))
    return;

  if (Call.getNumArgs() == 0)
    return;

  SVal ArgVal = Call.getArgSVal(0);
  SymbolRef Sym = getSymbolFromSVal(ArgVal);
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  const bool *Unchecked = State->get<UncheckedDupMap>(Sym);
  if (!Unchecked || !*Unchecked)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Duplicator result used in length_of before NULL check", N);

  if (const Expr *E = Call.getOriginExpr())
    Report->addRange(E->getSourceRange());

  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  Cond = Cond->IgnoreParenImpCasts();
  const Expr *PtrExpr = nullptr;

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      PtrExpr = UO->getSubExpr()->IgnoreParenImpCasts();
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSIsNull = isNullConstant(LHS, C);
      bool RHSIsNull = isNullConstant(RHS, C);

      if (LHSIsNull && !RHSIsNull)
        PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrExpr = LHS;
    }
  } else {
    // if (ptr) { ... }
    PtrExpr = Cond;
  }

  if (!PtrExpr)
    return;

  ProgramStateRef State = C.getState();
  SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
  SymbolRef Sym = getSymbolFromSVal(PtrVal);
  if (!Sym)
    return;

  const bool *Unchecked = State->get<UncheckedDupMap>(Sym);
  if (Unchecked && *Unchecked) {
    State = State->remove<UncheckedDupMap>(Sym);
    C.addTransition(State);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects duplicator results used in length_of before NULL checking",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "duplicator": {"names": ["xmlStrdup"], "description": "returns a newly allocated copy of its input; may return NULL on allocation failure"},
  "null_on_failure": {"names": ["xmlStrdup"], "description": "function that may return NULL when it fails"},
  "length_of": {"names": ["strlen"], "description": "computes the length of a NUL-terminated string; dereferences its pointer argument"},
  "allocator": {"names": ["xmlMalloc"], "description": "allocates a block of memory; returns NULL on failure"},
  "deallocator": {"names": ["xmlFree"], "description": "frees memory previously returned by the allocator"}
}
*/
