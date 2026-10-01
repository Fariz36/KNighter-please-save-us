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
#include "clang/AST/ASTContext.h"
#include "clang/AST/OperationKinds.h"
#include "llvm/ADT/SmallVector.h"
#include <algorithm>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Map from a symbolic pointer returned by xmlStrdup to whether it is still
// unchecked. true = produced by xmlStrdup and not yet compared against NULL.
REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedAllocMap, SymbolRef, bool)

namespace {

static bool isTrackedAllocFunction(const CallEvent &Call, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  return ExprHasName(OriginExpr, "xmlStrdup", C);
}

static bool isNullExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  if (E->isNullPointerConstant(C.getASTContext(),
                               Expr::NPC_ValueDependentIsNull))
    return true;
  llvm::APSInt Val;
  if (EvaluateExprToInt(Val, E, C))
    return Val == 0;
  return false;
}

// Strip parentheses and casts that are not LValueToRValue, so that we can
// obtain the underlying pointer expression for cases like `if (ptr)` or `!ptr`.
static const Expr *stripCastsToPointer(const Expr *E) {
  while (E) {
    E = E->IgnoreParens();
    if (const auto *Cast = dyn_cast<CastExpr>(E)) {
      if (Cast->getCastKind() != CK_LValueToRValue) {
        E = Cast->getSubExpr();
        continue;
      }
    }
    break;
  }
  return E;
}

static SymbolRef getSymbolFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  E = stripCastsToPointer(E);
  ProgramStateRef State = C.getState();
  SVal V = State->getSVal(E, C.getLocationContext());
  return V.getAsSymbol();
}

static SymbolRef getNullCheckedSymbol(const Stmt *Condition, CheckerContext &C) {
  if (!Condition)
    return nullptr;
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return nullptr;

  CondE = CondE->IgnoreParens();

  // Case 1: !ptr
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      return getSymbolFromExpr(UO->getSubExpr(), C);
    }
  }

  // Case 2: ptr == NULL, ptr != NULL, NULL == ptr, NULL != ptr
  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();

      bool LHSIsNull = isNullExpr(LHS, C);
      bool RHSIsNull = isNullExpr(RHS, C);
      const Expr *PtrExpr = nullptr;
      if (LHSIsNull && !RHSIsNull) {
        PtrExpr = RHS;
      } else if (RHSIsNull && !LHSIsNull) {
        PtrExpr = LHS;
      }
      if (PtrExpr) {
        return getSymbolFromExpr(PtrExpr, C);
      }
    }
  }

  // Case 3: if (ptr)
  return getSymbolFromExpr(CondE, C);
}

static ProgramStateRef markChecked(ProgramStateRef State, SymbolRef Sym) {
  return State->remove<UncheckedAllocMap>(Sym);
}

class SAGenTestChecker
    : public Checker<check::PostCall, check::BranchCondition, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use before NULL check", "Null Pointer")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isTrackedAllocFunction(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = RetVal.getAsSymbol();
  if (!Sym)
    return;

  State = State->set<UncheckedAllocMap>(Sym, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  SymbolRef Sym = getNullCheckedSymbol(Condition, C);
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  State = markChecked(State, Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  llvm::SmallVector<unsigned, 4> DerefParams;
  bool Known = functionKnownToDeref(Call, DerefParams);

  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (Callee && Callee->getName() == "strlen") {
    if (std::find(DerefParams.begin(), DerefParams.end(), 0) ==
        DerefParams.end())
      DerefParams.push_back(0);
    Known = true;
  }

  if (!Known)
    return;

  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    SVal ArgVal = Call.getArgSVal(Idx);
    SymbolRef Sym = ArgVal.getAsSymbol();
    if (!Sym)
      continue;

    const bool *Unchecked = State->get<UncheckedAllocMap>(Sym);
    if (Unchecked && *Unchecked) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Use of possibly-NULL pointer before NULL check", N);
      Report->addRange(Call.getSourceRange());
      C.emitReport(std::move(Report));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of pointers returned by xmlStrdup before NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
