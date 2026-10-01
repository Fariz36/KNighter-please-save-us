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

#include "clang/AST/Expr.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state: set of symbols returned by allocation/duplication functions
// that have not yet been checked against NULL.
REGISTER_SET_WITH_PROGRAMSTATE(UncheckedNullPtrs, SymbolRef)

namespace {

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreCall,
    check::BranchCondition,
    check::Location
> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use before NULL check", "Null Pointer")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  bool isAllocFunc(const CallEvent &Call, CheckerContext &C) const;
  bool isNullCheck(const Expr *Cond, const Expr *&PtrExpr, CheckerContext &C) const;
  void reportBug(const SourceRange &Range, CheckerContext &C, const char *Msg) const;
};

bool SAGenTestChecker::isAllocFunc(const CallEvent &Call, CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, "xmlStrdup", C) ||
         ExprHasName(E, "xmlMalloc", C) ||
         ExprHasName(E, "xmlRealloc", C) ||
         ExprHasName(E, "strdup", C) ||
         ExprHasName(E, "malloc", C);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isAllocFunc(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = RetVal.getAsLocSymbol();
  if (!Sym)
    return;

  State = State->add<UncheckedNullPtrs>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Explicitly handle strlen (the target bug uses strlen).
  if (ExprHasName(OriginExpr, "strlen", C)) {
    if (Call.getNumArgs() > 0) {
      SVal ArgVal = Call.getArgSVal(0);
      SymbolRef Sym = ArgVal.getAsLocSymbol();
      if (Sym && State->contains<UncheckedNullPtrs>(Sym)) {
        reportBug(Call.getSourceRange(), C, "Allocation result used before NULL check");
        return;
      }
    }
  }

  // General known-deref functions (from utility table).
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (functionKnownToDeref(Call, DerefParams)) {
    for (unsigned Idx : DerefParams) {
      if (Idx >= Call.getNumArgs())
        continue;
      SVal ArgVal = Call.getArgSVal(Idx);
      SymbolRef Sym = ArgVal.getAsLocSymbol();
      if (Sym && State->contains<UncheckedNullPtrs>(Sym)) {
        reportBug(Call.getSourceRange(), C, "Allocation result used before NULL check");
        return;
      }
    }
  }
}

bool SAGenTestChecker::isNullCheck(const Expr *Cond, const Expr *&PtrExpr, CheckerContext &C) const {
  if (!Cond)
    return false;
  Cond = Cond->IgnoreParenCasts();

  // Case 1: !ptr
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
      if (Sub->getType()->isPointerType()) {
        PtrExpr = Sub;
        return true;
      }
    }
  }

  // Case 2: ptr == NULL or ptr != NULL
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && !RHSIsNull && RHS->getType()->isPointerType()) {
        PtrExpr = RHS;
        return true;
      }
      if (RHSIsNull && !LHSIsNull && LHS->getType()->isPointerType()) {
        PtrExpr = LHS;
        return true;
      }
    }
  }

  // Case 3: ptr (implicit bool conversion)
  if (Cond->getType()->isPointerType()) {
    PtrExpr = Cond;
    return true;
  }

  return false;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond) {
    C.addTransition(C.getState());
    return;
  }

  const Expr *PtrExpr = nullptr;
  if (isNullCheck(Cond, PtrExpr, C)) {
    ProgramStateRef State = C.getState();
    SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
    SymbolRef Sym = PtrVal.getAsLocSymbol();
    if (Sym) {
      State = State->remove<UncheckedNullPtrs>(Sym);
      C.addTransition(State);
      return;
    }
  }
  C.addTransition(C.getState());
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SymbolRef Sym = Loc.getAsLocSymbol();
  if (Sym && State->contains<UncheckedNullPtrs>(Sym)) {
    reportBug(S->getSourceRange(), C, "Allocation result dereferenced before NULL check");
  }
}

void SAGenTestChecker::reportBug(const SourceRange &Range, CheckerContext &C, const char *Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  report->addRange(Range);
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of allocation/duplication function results before NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
