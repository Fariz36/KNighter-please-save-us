#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
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
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Set of symbols returned by null-on-failure allocator/duplicator functions
// that have not yet been checked for NULL.
REGISTER_SET_WITH_PROGRAMSTATE(UncheckedNullOnFailure, SymbolRef)

namespace {

class SAGenTestChecker
    : public Checker<check::PostCall,
                     check::PreCall,
                     check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Null-on-failure pointer used before null check",
                       "Null Pointer Dereference")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

/// Extract a SymbolRef from a pointer SVal.
static SymbolRef getPointerSymbol(SVal V) {
  if (SymbolRef Sym = V.getAsSymbol())
    return Sym;

  if (const MemRegion *R = V.getAsRegion()) {
    if (const auto *SymR = dyn_cast<SymbolicRegion>(R))
      return SymR->getSymbol();
  }

  return nullptr;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!(knighter::callIsRole(Call, "allocator") ||
        knighter::callIsRole(Call, "duplicator")))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = getPointerSymbol(Ret);
  if (!Sym)
    return;

  State = State->add<UncheckedNullOnFailure>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "length_of"))
    return;

  if (Call.getNumArgs() < 1)
    return;

  ProgramStateRef State = C.getState();
  SVal Arg = Call.getArgSVal(0);
  SymbolRef Sym = getPointerSymbol(Arg);
  if (!Sym)
    return;

  if (State->contains<UncheckedNullOnFailure>(Sym)) {
    reportBug(Call, C);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  CondE = CondE->IgnoreParenCasts();
  SymbolRef Sym = nullptr;

  // Handle: if (!ptr)
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr()->IgnoreParenCasts();
      SVal SubVal = State->getSVal(SubE, C.getLocationContext());
      Sym = getPointerSymbol(SubVal);
    }
  }
  // Handle: if (ptr == NULL) or if (ptr != NULL)
  else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

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
        SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
        Sym = getPointerSymbol(PtrVal);
      }
    }
  }
  // Handle bare pointer condition: if (ptr)
  else {
    SVal CondVal = State->getSVal(CondE, C.getLocationContext());
    Sym = getPointerSymbol(CondVal);
  }

  if (Sym && State->contains<UncheckedNullOnFailure>(Sym)) {
    State = State->remove<UncheckedNullOnFailure>(Sym);
  }

  C.addTransition(State);
}

void SAGenTestChecker::reportBug(const CallEvent &Call,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "NULL-on-failure pointer used by length function before NULL check",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects NULL-on-failure pointers used by length functions before NULL checks",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {"names": ["xmlStrdup"], "description": "memory allocation/duplication function that may return NULL on failure"},
  "duplicator": {"names": ["xmlStrdup"], "description": "string duplication function that may return NULL on failure"},
  "length_of": {"names": ["strlen"], "description": "function that computes string length and dereferences its pointer argument"},
  "deallocator": {"names": ["xmlFree"], "description": "function that frees memory allocated by allocator/duplicator"},
  "object_field": {"names": ["string"], "description": "struct field storing the pointer returned by allocator/duplicator"}
}
*/
