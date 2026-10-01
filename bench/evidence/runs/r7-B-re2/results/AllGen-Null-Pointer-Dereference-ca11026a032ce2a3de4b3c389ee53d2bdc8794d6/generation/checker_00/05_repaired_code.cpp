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
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Map from the symbol returned by a Walk call to the walker object region.
REGISTER_MAP_WITH_PROGRAMSTATE(ResultToWalkerMap, SymbolRef, const MemRegion *)
// Inverse map from the walker object region to the latest Walk result symbol.
REGISTER_MAP_WITH_PROGRAMSTATE(WalkerToResultMap, const MemRegion *, SymbolRef)

namespace {

class SAGenTestChecker
    : public Checker<check::PostCall,
                     check::PreCall,
                     check::PreStmt<ReturnStmt>,
                     check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked Walk Result", "Logic Error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;

private:
  void reportBug(const Stmt *S, CheckerContext &C) const;
};

static bool isWalkCall(const CallEvent &Call) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;

  const auto *MC = dyn_cast<CXXMemberCallExpr>(E);
  if (!MC)
    return false;

  const CXXMethodDecl *MD = MC->getMethodDecl();
  if (!MD)
    return false;

  if (MD->getNameAsString() != "Walk")
    return false;

  const CXXRecordDecl *RD = MD->getParent();
  if (!RD)
    return false;

  const std::string ClassName = RD->getNameAsString();
  return ClassName == "CoalesceWalker" || ClassName == "SimplifyWalker";
}

static bool isStoppedEarlyCall(const CallEvent &Call) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;

  const auto *MC = dyn_cast<CXXMemberCallExpr>(E);
  if (!MC)
    return false;

  const CXXMethodDecl *MD = MC->getMethodDecl();
  if (!MD)
    return false;

  return MD->getNameAsString() == "stopped_early";
}

static const MemRegion *getCXXObjectRegion(const CallEvent &Call,
                                           CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return nullptr;

  const auto *MC = dyn_cast<CXXMemberCallExpr>(E);
  if (!MC)
    return nullptr;

  const Expr *ObjE = MC->getImplicitObjectArgument();
  if (!ObjE)
    return nullptr;

  SVal ObjVal = C.getState()->getSVal(ObjE, C.getLocationContext());
  const MemRegion *MR = ObjVal.getAsRegion();
  if (MR)
    MR = MR->getBaseRegion();
  return MR;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isWalkCall(Call)) {
    SymbolRef ResultSym = Call.getReturnValue().getAsSymbol();
    if (!ResultSym)
      return;

    const MemRegion *WalkerReg = getCXXObjectRegion(Call, C);
    if (!WalkerReg)
      return;

    State = State->set<ResultToWalkerMap>(ResultSym, WalkerReg);
    State = State->set<WalkerToResultMap>(WalkerReg, ResultSym);
    C.addTransition(State);
    return;
  }

  if (isStoppedEarlyCall(Call)) {
    const MemRegion *WalkerReg = getCXXObjectRegion(Call, C);
    if (!WalkerReg)
      return;

    if (const SymbolRef *ResultSymPtr =
            State->get<WalkerToResultMap>(WalkerReg)) {
      SymbolRef ResultSym = *ResultSymPtr;
      State = State->remove<ResultToWalkerMap>(ResultSym);
      State = State->remove<WalkerToResultMap>(WalkerReg);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  auto IsUncheckedWalkResult = [&](SVal V) -> bool {
    SymbolRef Sym = V.getAsSymbol();
    return Sym && State->get<ResultToWalkerMap>(Sym) != nullptr;
  };

  for (unsigned I = 0, N = Call.getNumArgs(); I < N; ++I) {
    if (IsUncheckedWalkResult(Call.getArgSVal(I))) {
      reportBug(Call.getOriginExpr(), C);
      return;
    }
  }

  if (const auto *MC =
          dyn_cast_or_null<CXXMemberCallExpr>(Call.getOriginExpr())) {
    const Expr *ObjE = MC->getImplicitObjectArgument();
    if (ObjE) {
      SVal ObjVal = State->getSVal(ObjE, C.getLocationContext());
      if (IsUncheckedWalkResult(ObjVal)) {
        reportBug(Call.getOriginExpr(), C);
        return;
      }
    }
  }
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS,
                                    CheckerContext &C) const {
  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = State->getSVal(RetE, C.getLocationContext());
  SymbolRef Sym = RetVal.getAsSymbol();
  if (Sym && State->get<ResultToWalkerMap>(Sym)) {
    reportBug(RS, C);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;

  SymbolRef Sym = Loc.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  if (State->get<ResultToWalkerMap>(Sym)) {
    reportBug(S, C);
  }
}

void SAGenTestChecker::reportBug(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Walk result used without checking stopped_early()", N);
  if (S)
    Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of Walk results without checking stopped_early()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
