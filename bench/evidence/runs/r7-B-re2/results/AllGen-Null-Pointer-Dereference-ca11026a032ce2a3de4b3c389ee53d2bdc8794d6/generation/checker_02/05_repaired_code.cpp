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
#include "clang/AST/DeclCXX.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks whether a pointer returned by Regexp::Simplify() has been NULL-checked.
REGISTER_MAP_WITH_PROGRAMSTATE(PossibleNullPtrMap, const MemRegion *, bool)

// Tracks simple pointer aliasing so that a NULL-check on one pointer also
// marks its aliases as checked.
REGISTER_MAP_WITH_PROGRAMSTATE(PtrAliasMap, const MemRegion *, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::BranchCondition,
                                        check::Location,
                                        check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Null Dereference", "Null pointer")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                 CheckerContext &C) const;

private:
  void reportNullDeref(const CallEvent &Call, CheckerContext &C) const;
  void reportNullDeref(const Stmt *S, CheckerContext &C) const;
  void checkSVal(SVal V, const CallEvent &Call, CheckerContext &C) const;
  void setChecked(ProgramStateRef &State, const MemRegion *MR) const;
};

} // end anonymous namespace

static bool isRegexpSimplify(const CallEvent &Call) {
  if (const auto *MD = dyn_cast_or_null<CXXMethodDecl>(Call.getDecl())) {
    if (MD->getName() == "Simplify") {
      const CXXRecordDecl *RD = MD->getParent();
      if (RD && RD->getName() == "Regexp")
        return true;
    }
  }
  return false;
}

static bool isBuildInfo(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == "BuildInfo";
  return false;
}

static bool isDecref(const CallEvent &Call) {
  if (const auto *MD = dyn_cast_or_null<CXXMethodDecl>(Call.getDecl()))
    return MD->getName() == "Decref";
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == "Decref";
  return false;
}

void SAGenTestChecker::setChecked(ProgramStateRef &State,
                                  const MemRegion *MR) const {
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  const bool *Checked = State->get<PossibleNullPtrMap>(MR);
  if (Checked && *Checked == false)
    State = State->set<PossibleNullPtrMap>(MR, true);

  if (auto AliasReg = State->get<PtrAliasMap>(MR)) {
    const MemRegion *Alias = *AliasReg;
    if (Alias) {
      Alias = Alias->getBaseRegion();
      if (Alias) {
        const bool *AliasChecked = State->get<PossibleNullPtrMap>(Alias);
        if (AliasChecked && *AliasChecked == false)
          State = State->set<PossibleNullPtrMap>(Alias, true);
      }
    }
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isRegexpSimplify(Call))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  const MemRegion *MR = RetVal.getAsRegion();
  if (!MR) {
    const Expr *E = Call.getOriginExpr();
    if (E) {
      SVal V = State->getSVal(E, C.getLocationContext());
      MR = V.getAsRegion();
    }
  }
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  State = State->set<PossibleNullPtrMap>(MR, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkSVal(SVal V, const CallEvent &Call,
                                 CheckerContext &C) const {
  const MemRegion *MR = V.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<PossibleNullPtrMap>(MR);
  if (Checked && *Checked == false) {
    reportNullDeref(Call, C);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // BuildInfo(simple) dereferences its first argument.
  if (isBuildInfo(Call) && Call.getNumArgs() > 0) {
    checkSVal(Call.getArgSVal(0), Call, C);
  }

  // simple->Decref() dereferences the implicit object.
  if (isDecref(Call)) {
    if (const auto *CMCE = dyn_cast_or_null<CXXMemberCallExpr>(
            Call.getOriginExpr())) {
      const Expr *ObjE = CMCE->getImplicitObjectArgument();
      if (ObjE) {
        SVal ObjVal = State->getSVal(ObjE, C.getLocationContext());
        checkSVal(ObjVal, Call, C);
      }
    }
  }

  // Generic known-to-deref functions.
  llvm::SmallVector<unsigned, 4> DerefParams;
  if (functionKnownToDeref(Call, DerefParams)) {
    for (unsigned Idx : DerefParams) {
      if (Idx < Call.getNumArgs())
        checkSVal(Call.getArgSVal(Idx), Call, C);
    }
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

  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *SubE = UO->getSubExpr()->IgnoreParenCasts();
      SVal SubVal = State->getSVal(SubE, C.getLocationContext());
      if (const MemRegion *MR = SubVal.getAsRegion()) {
        setChecked(State, MR->getBaseRegion());
      }
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
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
        if (const MemRegion *MR = PtrVal.getAsRegion()) {
          setChecked(State, MR->getBaseRegion());
        }
      }
    }
  } else {
    SVal CondVal = State->getSVal(CondE, C.getLocationContext());
    if (const MemRegion *MR = CondVal.getAsRegion()) {
      setChecked(State, MR->getBaseRegion());
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<PossibleNullPtrMap>(MR);
  if (Checked && *Checked == false) {
    reportNullDeref(S, C);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  const MemRegion *RHSReg = Val.getAsRegion();
  if (!RHSReg)
    return;
  RHSReg = RHSReg->getBaseRegion();
  if (!RHSReg)
    return;

  State = State->set<PtrAliasMap>(LHSReg, RHSReg);
  State = State->set<PtrAliasMap>(RHSReg, LHSReg);
  C.addTransition(State);
}

void SAGenTestChecker::reportNullDeref(const CallEvent &Call,
                                       CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Possible NULL dereference: Regexp::Simplify() may return NULL.", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

void SAGenTestChecker::reportNullDeref(const Stmt *S,
                                       CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Possible NULL dereference: Regexp::Simplify() may return NULL.", N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dereferences of pointers returned by Regexp::Simplify without NULL checks",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
