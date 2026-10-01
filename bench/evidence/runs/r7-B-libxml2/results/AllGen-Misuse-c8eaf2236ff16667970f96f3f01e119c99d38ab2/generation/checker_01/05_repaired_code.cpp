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
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Map from the MemRegion of an xmlParserCtxt object to a boolean flag.
// true  -> maxAmpl may be zero (unchecked)
// false -> maxAmpl is known to be non-zero
REGISTER_MAP_WITH_PROGRAMSTATE(MaxAmplZeroMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<
    check::PostCall,
    check::BranchCondition,
    check::PreStmt<BinaryOperator>
> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Division by zero", "Arithmetic")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;

private:
  const MemRegion *getCtxtRegionFromMaxAmplExpr(const Expr *E,
                                                 CheckerContext &C) const;
  void markMaxAmplZero(ProgramStateRef &State, const MemRegion *CtxtRegion,
                       bool Zero) const;
  void reportDivisionByZero(const BinaryOperator *BO, CheckerContext &C) const;
};

} // end anonymous namespace

// Helper: check if the expression is a MemberExpr accessing "maxAmpl".
static bool isMaxAmplMemberExpr(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenCasts();
  const auto *ME = dyn_cast<MemberExpr>(E);
  if (!ME)
    return false;
  const ValueDecl *VD = ME->getMemberDecl();
  return VD && VD->getName() == "maxAmpl";
}

// Extract the MemRegion of the xmlParserCtxt object from an expression
// that accesses its "maxAmpl" field.
const MemRegion *
SAGenTestChecker::getCtxtRegionFromMaxAmplExpr(const Expr *E,
                                               CheckerContext &C) const {
  if (!E)
    return nullptr;
  E = E->IgnoreParenCasts();
  const auto *ME = dyn_cast<MemberExpr>(E);
  if (!ME)
    return nullptr;

  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD || VD->getName() != "maxAmpl")
    return nullptr;

  const Expr *Base = ME->getBase();
  if (!Base)
    return nullptr;

  const MemRegion *Region = getMemRegionFromExpr(Base, C);
  if (!Region)
    return nullptr;

  return Region->getBaseRegion();
}

void SAGenTestChecker::markMaxAmplZero(ProgramStateRef &State,
                                       const MemRegion *CtxtRegion,
                                       bool Zero) const {
  if (!CtxtRegion)
    return;
  State = State->set<MaxAmplZeroMap>(CtxtRegion, Zero);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "xmlCtxtSetMaxAmplification", C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const Expr *CtxtExpr = Call.getArgExpr(0);
  if (!CtxtExpr)
    return;

  const MemRegion *CtxtRegion = getMemRegionFromExpr(CtxtExpr, C);
  if (!CtxtRegion)
    return;
  CtxtRegion = CtxtRegion->getBaseRegion();
  if (!CtxtRegion)
    return;

  const Expr *MaxAmplExpr = Call.getArgExpr(1);
  if (!MaxAmplExpr)
    return;

  ProgramStateRef State = C.getState();
  llvm::APSInt EvalRes;
  bool PossiblyZero = true;
  if (EvaluateExprToInt(EvalRes, MaxAmplExpr, C)) {
    PossiblyZero = (EvalRes == 0);
  } else {
    PossiblyZero = true;
  }

  markMaxAmplZero(State, CtxtRegion, PossiblyZero);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();
  const Expr *MaxAmplExpr = nullptr;

  CondE = CondE->IgnoreParenCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_GT || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      llvm::APSInt Zero;
      bool LHSIsZero = EvaluateExprToInt(Zero, LHS, C) && Zero == 0;
      bool RHSIsZero = EvaluateExprToInt(Zero, RHS, C) && Zero == 0;

      if (isMaxAmplMemberExpr(LHS) && RHSIsZero) {
        MaxAmplExpr = LHS;
      } else if (isMaxAmplMemberExpr(RHS) && LHSIsZero) {
        MaxAmplExpr = RHS;
      }
    }
  } else if (isMaxAmplMemberExpr(CondE)) {
    MaxAmplExpr = CondE;
  }

  if (MaxAmplExpr) {
    const MemRegion *CtxtRegion =
        getCtxtRegionFromMaxAmplExpr(MaxAmplExpr, C);
    if (CtxtRegion) {
      markMaxAmplZero(State, CtxtRegion, false);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO,
                                    CheckerContext &C) const {
  if (BO->getOpcode() != BO_Div)
    return;

  const Expr *Denom = BO->getRHS();
  if (!Denom)
    return;

  const MemRegion *CtxtRegion = getCtxtRegionFromMaxAmplExpr(Denom, C);
  if (!CtxtRegion)
    return;

  ProgramStateRef State = C.getState();
  const bool *PossiblyZero = State->get<MaxAmplZeroMap>(CtxtRegion);
  if (PossiblyZero && *PossiblyZero) {
    reportDivisionByZero(BO, C);
  }
}

void SAGenTestChecker::reportDivisionByZero(const BinaryOperator *BO,
                                            CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Division by zero: maxAmpl may be 0", N);
  report->addRange(BO->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects division by zero when maxAmpl may be zero",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
