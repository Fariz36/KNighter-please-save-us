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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "llvm/ADT/APSInt.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedAllocMap, SymbolRef, bool)

namespace {

static SymbolRef getSymbolFromSVal(SVal Val) {
  if (SymbolRef Sym = Val.getAsSymbol())
    return Sym;

  if (const MemRegion *MR = Val.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(MR))
      return SR->getSymbol();
  }

  return nullptr;
}

static bool isNullConstant(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

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
      : BT(new BugType(this, "Use Before NULL Check", "Null Pointer")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee || Callee->getName() != "xmlStrdup")
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = getSymbolFromSVal(RetVal);
  if (!Sym)
    return;

  State = State->set<UncheckedAllocMap>(Sym, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  llvm::SmallVector<unsigned, 4> DerefParams;
  functionKnownToDeref(Call, DerefParams);

  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (Callee && Callee->getName() == "strlen") {
    bool HasZero = false;
    for (unsigned Idx : DerefParams) {
      if (Idx == 0) {
        HasZero = true;
        break;
      }
    }
    if (!HasZero)
      DerefParams.push_back(0);
  }

  if (DerefParams.empty())
    return;

  ProgramStateRef State = C.getState();
  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    SVal ArgVal = Call.getArgSVal(Idx);
    SymbolRef Sym = getSymbolFromSVal(ArgVal);
    if (!Sym)
      continue;

    const bool *Unchecked = State->get<UncheckedAllocMap>(Sym);
    if (Unchecked && *Unchecked) {
      reportBug(Call, C);
      return;
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();
  CondE = CondE->IgnoreParenCasts();

  const Expr *PtrExpr = nullptr;

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot)
      PtrExpr = UO->getSubExpr()->IgnoreParenCasts();
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      bool LHSIsNull = isNullConstant(LHS, C);
      bool RHSIsNull = isNullConstant(RHS, C);

      if (LHSIsNull && !RHSIsNull)
        PtrExpr = RHS;
      else if (RHSIsNull && !LHSIsNull)
        PtrExpr = LHS;
    }
  } else {
    PtrExpr = CondE;
  }

  if (PtrExpr) {
    SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
    SymbolRef Sym = getSymbolFromSVal(PtrVal);
    if (Sym) {
      if (State->get<UncheckedAllocMap>(Sym)) {
        State = State->remove<UncheckedAllocMap>(Sym);
        C.addTransition(State);
        return;
      }
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::reportBug(const CallEvent &Call,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Use of unchecked allocation result before NULL check", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of xmlStrdup result before NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
