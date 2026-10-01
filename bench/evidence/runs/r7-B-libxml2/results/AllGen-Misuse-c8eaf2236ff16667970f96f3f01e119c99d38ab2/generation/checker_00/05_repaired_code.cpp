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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include <memory>
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(PossiblyZeroDivisors, const MemRegion *)

namespace {

class SAGenTestChecker
    : public Checker<check::PreCall, check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this, "Division by zero", "Logic Error")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;

private:
  void reportDivisionByZero(const BinaryOperator *BO, CheckerContext &C) const;
};

} // end anonymous namespace

static bool isSetMaxAmplification(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, "xmlCtxtSetMaxAmplification", C);
}

static const FieldDecl *getFieldDecl(QualType Ty, StringRef Name) {
  Ty = Ty.getCanonicalType();
  const PointerType *PT = Ty->getAs<PointerType>();
  if (!PT)
    return nullptr;

  QualType PointeeTy = PT->getPointeeType().getCanonicalType();
  const RecordType *RT = PointeeTy->getAs<RecordType>();
  if (!RT)
    return nullptr;

  RecordDecl *RD = RT->getDecl();
  for (FieldDecl *FD : RD->fields()) {
    if (FD->getName() == Name)
      return FD;
  }
  return nullptr;
}

static const MemRegion *getFieldRegion(ProgramStateRef State,
                                       const Expr *CtxtArg,
                                       const MemRegion *BaseReg,
                                       StringRef Name) {
  if (!CtxtArg || !BaseReg)
    return nullptr;

  const FieldDecl *FD = getFieldDecl(CtxtArg->getType(), Name);
  if (!FD)
    return nullptr;

  return State->getLValue(FD, loc::MemRegionVal(BaseReg)).getAsRegion();
}

static const MemRegion *getFieldRegionFromExpr(const Expr *E,
                                                CheckerContext &C,
                                                ProgramStateRef State) {
  if (!E)
    return nullptr;

  const Expr *Ignored = E->IgnoreParenImpCasts();
  const MemberExpr *ME = dyn_cast<MemberExpr>(Ignored);
  if (!ME)
    return nullptr;

  const ValueDecl *VD = ME->getMemberDecl();
  const FieldDecl *FD = dyn_cast<FieldDecl>(VD);
  if (!FD)
    return nullptr;

  const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
  const MemRegion *BaseReg = getMemRegionFromExpr(Base, C);
  if (!BaseReg)
    return nullptr;

  return State->getLValue(FD, loc::MemRegionVal(BaseReg)).getAsRegion();
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isSetMaxAmplification(Call, C))
    return;
  if (Call.getNumArgs() < 2)
    return;

  const Expr *CtxtArg = Call.getArgExpr(0);
  const Expr *MaxAmplArg = Call.getArgExpr(1);
  if (!CtxtArg || !MaxAmplArg)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *CtxtRegion = getMemRegionFromExpr(CtxtArg, C);
  if (!CtxtRegion)
    return;

  const MemRegion *FieldReg = getFieldRegion(State, CtxtArg, CtxtRegion, "maxAmpl");
  if (!FieldReg)
    return;

  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, MaxAmplArg, C)) {
    if (!EvalRes.isZero())
      State = State->remove<PossiblyZeroDivisors>(FieldReg);
    else
      State = State->add<PossiblyZeroDivisors>(FieldReg);
  } else {
    State = State->add<PossiblyZeroDivisors>(FieldReg);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO,
                                    CheckerContext &C) const {
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_Div && Op != BO_Rem)
    return;

  const Expr *RHS = BO->getRHS();
  if (!RHS)
    return;

  const Expr *RHSIgnored = RHS->IgnoreParenImpCasts();
  ProgramStateRef State = C.getState();
  const MemRegion *MR = getFieldRegionFromExpr(RHSIgnored, C, State);
  if (!MR)
    return;

  if (!State->contains<PossiblyZeroDivisors>(MR))
    return;

  SVal RHSVal = State->getSVal(RHSIgnored, C.getLocationContext());
  if (std::optional<nonloc::ConcreteInt> CI = RHSVal.getAs<nonloc::ConcreteInt>()) {
    if (CI->getValue().isZero())
      reportDivisionByZero(BO, C);
    return;
  }

  if (SymbolRef Sym = RHSVal.getAsSymbol()) {
    const llvm::APSInt *MinVal =
        State->getConstraintManager().getSymMinVal(State, Sym);
    if (!MinVal || MinVal->isZero())
      reportDivisionByZero(BO, C);
  }
}

void SAGenTestChecker::reportDivisionByZero(const BinaryOperator *BO,
                                            CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Division by possibly zero value 'maxAmpl'", N);
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects division by potentially zero maxAmpl after "
      "xmlCtxtSetMaxAmplification",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
