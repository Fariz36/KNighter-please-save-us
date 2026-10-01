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
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedAllocMap, SymbolRef, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use of allocation result before NULL check",
                       "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

static bool isAllocCopyFunc(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, "xmlStrdup", C);
}

static SymbolRef getSymbolFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;

  ProgramStateRef State = C.getState();
  SVal V = State->getSVal(E, C.getLocationContext());
  SymbolRef Sym = V.getAsSymbol();
  if (Sym)
    return Sym;

  // Try stripping explicit casts and parentheses.
  if (const Expr *E2 = E->IgnoreParenCasts()) {
    if (E2 != E) {
      V = State->getSVal(E2, C.getLocationContext());
      Sym = V.getAsSymbol();
    }
  }
  return Sym;
}

static SymbolRef getNullCheckedSymbol(const Expr *Cond, CheckerContext &C) {
  if (!Cond)
    return nullptr;

  // Handle !ptr
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      return getSymbolFromExpr(Sub, C);
    }
  }

  // Handle ptr == NULL or ptr != NULL
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      ASTContext &AC = C.getASTContext();
      bool LHSIsNull = LHS->isNullPointerConstant(
          AC, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          AC, Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull && !RHSIsNull)
        return getSymbolFromExpr(RHS, C);
      if (RHSIsNull && !LHSIsNull)
        return getSymbolFromExpr(LHS, C);
    }
  }

  // Handle implicit bool cast, e.g., if (ptr)
  return getSymbolFromExpr(Cond->IgnoreParenImpCasts(), C);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isAllocCopyFunc(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SymbolRef Sym = Call.getReturnValue().getAsSymbol();
  if (!Sym)
    return;

  State = State->set<UncheckedAllocMap>(Sym, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (!functionKnownToDeref(Call, DerefParams))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *Arg = Call.getArgExpr(Idx);
    if (!Arg)
      continue;

    SymbolRef Sym = getSymbolFromExpr(Arg, C);
    if (!Sym)
      continue;

    const bool *Unchecked = State->get<UncheckedAllocMap>(Sym);
    if (Unchecked && *Unchecked) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        continue;

      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Use of allocation result before NULL check", N);
      Report->addRange(Arg->getSourceRange());
      C.emitReport(std::move(Report));
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  SymbolRef Sym = getNullCheckedSymbol(CondE, C);
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  const bool *Unchecked = State->get<UncheckedAllocMap>(Sym);
  if (Unchecked && *Unchecked) {
    State = State->set<UncheckedAllocMap>(Sym, false);
    C.addTransition(State);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of allocation/copy function result before NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
