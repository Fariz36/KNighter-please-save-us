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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedDivisorMap, const MemRegion *, bool)

namespace {

static bool isDivisorField(const FieldDecl *FD) {
  return FD && knighter::declIsRole(FD, "divisor");
}

static bool isZeroConstant(const Expr *E, ASTContext &Ctx) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  Expr::EvalResult Res;
  if (E->EvaluateAsInt(Res, Ctx))
    return Res.Val.getInt().isZero();
  return false;
}

static const MemRegion *getDivisorRegion(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;

  auto checkRegion = [&](const MemRegion *R) -> const MemRegion * {
    if (!R)
      return nullptr;
    if (const auto *FR = dyn_cast<FieldRegion>(R)) {
      if (isDivisorField(FR->getDecl()))
        return FR;
    }
    if (const auto *VR = dyn_cast<VarRegion>(R)) {
      if (knighter::declIsRole(VR->getDecl(), "divisor"))
        return VR;
    }
    return nullptr;
  };

  if (const MemRegion *R = checkRegion(getMemRegionFromExpr(E, C)))
    return R;

  const Expr *Ignored = E->IgnoreParenImpCasts();
  if (Ignored != E) {
    if (const MemRegion *R = checkRegion(getMemRegionFromExpr(Ignored, C)))
      return R;
  }

  return nullptr;
}

static const MemRegion *extractNonZeroGuardRegion(const Expr *E,
                                                  CheckerContext &C) {
  if (!E)
    return nullptr;
  E = E->IgnoreParens();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      if (const MemRegion *R = extractNonZeroGuardRegion(BO->getLHS(), C))
        return R;
      return extractNonZeroGuardRegion(BO->getRHS(), C);
    }

    if (BO->getOpcode() == BO_NE || BO->getOpcode() == BO_GT ||
        BO->getOpcode() == BO_LT) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();
      if (isZeroConstant(RHS, C.getASTContext()))
        if (const MemRegion *R = getDivisorRegion(LHS, C))
          return R;
      if (isZeroConstant(LHS, C.getASTContext()))
        if (const MemRegion *R = getDivisorRegion(RHS, C))
          return R;
    }
  }

  if (const MemRegion *R = getDivisorRegion(E, C))
    return R;
  return nullptr;
}

static bool mayBeZero(SVal V, ProgramStateRef State) {
  if (V.isUnknown())
    return true;
  if (const auto CI = V.getAs<nonloc::ConcreteInt>())
    return CI->getValue().isZero();

  if (const auto DV = V.getAs<DefinedSVal>()) {
    ProgramStateRef ZeroState =
        State->getConstraintManager().assume(State, *DV, false);
    return ZeroState != nullptr;
  }
  return true;
}

static ProgramStateRef markUnchecked(ProgramStateRef State,
                                     const MemRegion *R) {
  return State->set<UncheckedDivisorMap>(R, true);
}

static ProgramStateRef markChecked(ProgramStateRef State,
                                   const MemRegion *R) {
  return State->remove<UncheckedDivisorMap>(R);
}

class SetterInfoVisitor
    : public RecursiveASTVisitor<SetterInfoVisitor> {
  const FunctionDecl *FD;
  unsigned &ObjIdx;
  unsigned &ValIdx;
  const FieldDecl *&Field;

public:
  bool Found = false;

  SetterInfoVisitor(const FunctionDecl *FD, unsigned &ObjIdx,
                    unsigned &ValIdx, const FieldDecl *&Field)
      : FD(FD), ObjIdx(ObjIdx), ValIdx(ValIdx), Field(Field) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (Found)
      return true;
    if (!BO || BO->getOpcode() != BO_Assign)
      return true;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

    const auto *ME = dyn_cast<MemberExpr>(LHS);
    if (!ME)
      return true;

    const auto *FDcl = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!isDivisorField(FDcl))
      return true;

    const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
    const auto *BaseDRE = dyn_cast<DeclRefExpr>(Base);
    if (!BaseDRE)
      return true;

    const auto *BasePVD = dyn_cast<ParmVarDecl>(BaseDRE->getDecl());
    if (!BasePVD || BasePVD->getDeclContext() != FD)
      return true;

    const auto *RHSDRE = dyn_cast<DeclRefExpr>(RHS);
    if (!RHSDRE)
      return true;

    const auto *ValPVD = dyn_cast<ParmVarDecl>(RHSDRE->getDecl());
    if (!ValPVD || ValPVD->getDeclContext() != FD)
      return true;

    Field = FDcl;
    ObjIdx = BasePVD->getFunctionScopeIndex();
    ValIdx = ValPVD->getFunctionScopeIndex();
    Found = true;
    return true;
  }
};

static bool getSetterInfo(const FunctionDecl *FD, unsigned &ObjIdx,
                          unsigned &ValIdx, const FieldDecl *&Field) {
  if (!FD || !FD->getBody())
    return false;
  SetterInfoVisitor V(FD, ObjIdx, ValIdx, Field);
  V.TraverseStmt(FD->getBody());
  return V.Found;
}

static bool isParamRef(const Expr *E, const FunctionDecl *FD, unsigned ValIdx) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return false;
  const auto *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  return PVD && PVD->getDeclContext() == FD &&
         PVD->getFunctionScopeIndex() == ValIdx;
}

static bool isParamZeroCheck(const Expr *Cond, const FunctionDecl *FD,
                             unsigned ValIdx) {
  if (!Cond)
    return false;
  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot)
      return isParamRef(UO->getSubExpr(), FD, ValIdx);
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();
      if (isParamRef(LHS, FD, ValIdx) &&
          isZeroConstant(RHS, FD->getASTContext()))
        return true;
      if (isParamRef(RHS, FD, ValIdx) &&
          isZeroConstant(LHS, FD->getASTContext()))
        return true;
    }
  }
  return false;
}

class ReturnOrBreakVisitor
    : public RecursiveASTVisitor<ReturnOrBreakVisitor> {
public:
  bool Found = false;

  bool VisitReturnStmt(ReturnStmt *RS) {
    Found = true;
    return false;
  }

  bool VisitBreakStmt(BreakStmt *BS) {
    Found = true;
    return false;
  }
};

static bool containsReturnOrBreak(const Stmt *S) {
  if (!S)
    return false;
  ReturnOrBreakVisitor V;
  V.TraverseStmt(const_cast<Stmt *>(S));
  return V.Found;
}

class ZeroGuardVisitor : public RecursiveASTVisitor<ZeroGuardVisitor> {
  const FunctionDecl *FD;
  unsigned ValIdx;

public:
  bool Found = false;

  ZeroGuardVisitor(const FunctionDecl *FD, unsigned ValIdx)
      : FD(FD), ValIdx(ValIdx) {}

  bool VisitIfStmt(IfStmt *IS) {
    if (Found)
      return true;
    if (!IS)
      return true;
    if (isParamZeroCheck(IS->getCond(), FD, ValIdx) &&
        containsReturnOrBreak(IS->getThen())) {
      Found = true;
      return false;
    }
    return true;
  }
};

static bool setterRejectsZero(const FunctionDecl *FD, unsigned ValIdx) {
  if (!FD || !FD->getBody())
    return false;
  ZeroGuardVisitor V(FD, ValIdx);
  V.TraverseStmt(FD->getBody());
  return V.Found;
}

class SAGenTestChecker
    : public Checker<check::Bind, check::PostCall, check::BranchCondition,
                     check::PostStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Division by possibly zero divisor",
                       "Integer division by zero")) {}

  void checkBind(SVal LocVal, SVal Val, const Stmt *StoreE,
                 CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPostStmt(const BinaryOperator *BO, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBind(SVal LocVal, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  const MemRegion *R = LocVal.getAsRegion();
  if (!R)
    return;

  const auto *FR = dyn_cast<FieldRegion>(R);
  if (!FR)
    return;

  const FieldDecl *FD = FR->getDecl();
  if (!isDivisorField(FD))
    return;

  ProgramStateRef State = C.getState();
  if (mayBeZero(Val, State))
    State = markUnchecked(State, R);
  else
    State = markChecked(State, R);

  C.addTransition(State);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "divisor_setter"))
    return;

  const Decl *D = Call.getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return;

  unsigned ObjIdx = 0, ValIdx = 0;
  const FieldDecl *Field = nullptr;
  if (!getSetterInfo(FD, ObjIdx, ValIdx, Field))
    return;

  if (setterRejectsZero(FD, ValIdx))
    return;

  if (ValIdx >= Call.getNumArgs() || ObjIdx >= Call.getNumArgs())
    return;

  SVal Val = Call.getArgSVal(ValIdx);
  if (!mayBeZero(Val, C.getState()))
    return;

  SVal Obj = Call.getArgSVal(ObjIdx);
  if (!Obj.getAs<Loc>())
    return;

  SVal FieldLoc = C.getState()->getLValue(Field, Obj);
  const MemRegion *R = FieldLoc.getAsRegion();
  if (!R)
    return;

  ProgramStateRef State = markUnchecked(C.getState(), R);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *E = dyn_cast<Expr>(Condition);
  if (!E)
    return;

  const MemRegion *R = extractNonZeroGuardRegion(E, C);
  if (!R)
    return;

  ProgramStateRef State = markChecked(C.getState(), R);
  C.addTransition(State);
}

void SAGenTestChecker::checkPostStmt(const BinaryOperator *BO,
                                     CheckerContext &C) const {
  if (!BO)
    return;
  if (BO->getOpcode() != BO_Div)
    return;

  const Expr *RHS = BO->getRHS();
  const MemRegion *R = getDivisorRegion(RHS, C);
  if (!R)
    return;

  ProgramStateRef State = C.getState();
  if (!State->get<UncheckedDivisorMap>(R))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Division by possibly zero divisor", N);
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects division by possibly zero divisor fields",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "divisor_setter": {
    "names": ["xmlCtxtSetMaxAmplification"],
    "description": "setter function that stores a value into a divisor field/object, possibly allowing zero"
  },
  "divisor": {
    "names": ["maxAmpl"],
    "description": "field or variable that is used as a divisor in a division expression"
  }
}
*/
