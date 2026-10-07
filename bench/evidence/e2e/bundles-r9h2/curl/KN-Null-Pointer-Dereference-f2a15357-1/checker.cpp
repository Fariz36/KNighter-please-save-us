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
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/STLExtras.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps
REGISTER_MAP_WITH_PROGRAMSTATE(OutParamMap, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(AliasMap, const MemRegion *, const MemRegion *)

namespace {

class SAGenTestChecker; // forward declaration

static const ParmVarDecl *getParameterFromExpr(const Expr *E, const FunctionDecl *FD) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
      if (PVD->getDeclContext() == FD) return PVD;
    }
  }
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      return getParameterFromExpr(UO->getSubExpr(), FD);
    }
  }
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    return getParameterFromExpr(ASE->getBase(), FD);
  }
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (ME->isArrow()) {
      return getParameterFromExpr(ME->getBase(), FD);
    }
  }
  return nullptr;
}

static bool isKnownNonNull(ProgramStateRef State, SVal PtrVal) {
  if (SymbolRef Sym = PtrVal.getAsSymbol()) {
    ConditionTruthVal NotNull = State->getConstraintManager().isNull(State, Sym);
    return NotNull.isConstrained() && !NotNull.getValue();
  }
  if (auto CI = PtrVal.getAs<loc::ConcreteInt>()) {
    return CI->getValue() != 0;
  }
  return false;
}

class OutParamVisitor : public RecursiveASTVisitor<OutParamVisitor> {
  const FunctionDecl *FD;
  llvm::SmallVectorImpl<unsigned> &OutParams;
  llvm::DenseMap<const ParmVarDecl *, unsigned> ParamIndexMap;
  const SAGenTestChecker &Checker;

public:
  OutParamVisitor(const FunctionDecl *FD, llvm::SmallVectorImpl<unsigned> &OutParams,
                  const SAGenTestChecker &Checker)
      : FD(FD), OutParams(OutParams), Checker(Checker) {
    for (unsigned i = 0; i < FD->getNumParams(); ++i) {
      ParamIndexMap[FD->getParamDecl(i)] = i;
    }
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->isAssignmentOp()) {
      const Expr *LHS = BO->getLHS();
      if (const ParmVarDecl *PVD = getParameterFromExpr(LHS, FD)) {
        unsigned idx = ParamIndexMap[PVD];
        if (!llvm::is_contained(OutParams, idx))
          OutParams.push_back(idx);
      }
    }
    return true;
  }

  bool VisitCallExpr(CallExpr *CE);
};

class SAGenTestChecker : public Checker<
    check::BeginFunction,
    check::Bind,
    check::PreCall
> {
  mutable std::unique_ptr<BugType> BT;
  mutable llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<unsigned, 4>> OutParamCache;
  mutable llvm::DenseSet<const FunctionDecl *> ComputingSet;

public:
  SAGenTestChecker() : BT(std::make_unique<BugType>(this, "Out-parameter written without NULL check", "API Misuse")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  llvm::SmallVector<unsigned, 4> getOutParamIndices(const FunctionDecl *FD) const;
  void reportBug(const MemRegion *MR, const Stmt *S, CheckerContext &C) const;
};

bool OutParamVisitor::VisitCallExpr(CallExpr *CE) {
  if (const FunctionDecl *CalleeFD = CE->getDirectCallee()) {
    auto CalleeOutParams = Checker.getOutParamIndices(CalleeFD);
    for (unsigned idx : CalleeOutParams) {
      if (idx < CE->getNumArgs()) {
        const Expr *Arg = CE->getArg(idx);
        if (const ParmVarDecl *PVD = getParameterFromExpr(Arg, FD)) {
          unsigned paramIdx = ParamIndexMap[PVD];
          if (!llvm::is_contained(OutParams, paramIdx))
            OutParams.push_back(paramIdx);
        }
      }
    }
  }
  return true;
}

llvm::SmallVector<unsigned, 4> SAGenTestChecker::getOutParamIndices(const FunctionDecl *FD) const {
  auto it = OutParamCache.find(FD);
  if (it != OutParamCache.end())
    return it->second;

  if (ComputingSet.count(FD)) {
    return {}; // break cycle
  }

  ComputingSet.insert(FD);

  llvm::SmallVector<unsigned, 4> OutParams;
  if (FD->hasBody()) {
    OutParamVisitor Visitor(FD, OutParams, *this);
    Visitor.TraverseStmt(FD->getBody());
  }

  OutParamCache[FD] = OutParams;
  ComputingSet.erase(FD);
  return OutParams;
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD) return;
  if (!knighter::declIsRole(FD, "out_param_api"))
    return;

  auto OutParams = getOutParamIndices(FD);
  if (OutParams.empty()) return;

  ProgramStateRef State = C.getState();
  for (unsigned idx : OutParams) {
    if (idx >= FD->getNumParams()) continue;
    const ParmVarDecl *PVD = FD->getParamDecl(idx);
    const MemRegion *MR = State->getLValue(PVD, C.getLocationContext()).getAsRegion();
    if (!MR) continue;
    MR = MR->getBaseRegion();
    if (!MR) continue;
    State = State->set<OutParamMap>(MR, false);
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD || !knighter::declIsRole(FD, "out_param_api"))
    return;

  ProgramStateRef State = C.getState();

  // Alias tracking
  if (const MemRegion *LocReg = Loc.getAsRegion()) {
    LocReg = LocReg->getBaseRegion();
    if (const MemRegion *ValReg = Val.getAsRegion()) {
      ValReg = ValReg->getBaseRegion();
      State = State->set<AliasMap>(LocReg, ValReg);
      State = State->set<AliasMap>(ValReg, LocReg);
    }
  }

  // Write detection
  if (S) {
    if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->isAssignmentOp()) {
        const Expr *LHS = BO->getLHS();
        if (const ParmVarDecl *PVD = getParameterFromExpr(LHS, FD)) {
          const MemRegion *MR = State->getLValue(PVD, C.getLocationContext()).getAsRegion();
          if (MR) {
            MR = MR->getBaseRegion();
            const bool *Checked = State->get<OutParamMap>(MR);
            if (Checked) { // It's an out-param
              SVal PtrVal = State->getSVal(MR);
              if (!isKnownNonNull(State, PtrVal)) {
                reportBug(MR, S, C);
              }
            }
          }
        }
      }
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD || !knighter::declIsRole(FD, "out_param_api"))
    return;

  ProgramStateRef State = C.getState();
  const Expr *CallExpr = Call.getOriginExpr();
  if (!CallExpr) return;

  const FunctionDecl *CalleeFD = Call.getDecl() ? dyn_cast<FunctionDecl>(Call.getDecl()) : nullptr;
  if (!CalleeFD) return;

  auto CalleeOutParams = getOutParamIndices(CalleeFD);
  if (CalleeOutParams.empty()) return;

  for (unsigned idx : CalleeOutParams) {
    if (idx >= Call.getNumArgs()) continue;
    const Expr *Arg = Call.getArgExpr(idx);
    if (!Arg) continue;
    if (const ParmVarDecl *PVD = getParameterFromExpr(Arg, FD)) {
      const MemRegion *MR = State->getLValue(PVD, C.getLocationContext()).getAsRegion();
      if (MR) {
        MR = MR->getBaseRegion();
        const bool *Checked = State->get<OutParamMap>(MR);
        if (Checked) {
          SVal PtrVal = State->getSVal(MR);
          if (!isKnownNonNull(State, PtrVal)) {
            reportBug(MR, CallExpr, C);
          }
        }
      }
    }
  }
}

void SAGenTestChecker::reportBug(const MemRegion *MR, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Out-parameter may be NULL and is written without a NULL check", N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects out-parameters written without NULL check in API functions",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "out_param_api": {
    "names": ["curl_easy_send", "curl_easy_recv"],
    "description": "public API function that accepts a caller-supplied pointer used as an output/write destination for a result; the pointer must be checked for NULL before being written through."
  }
}
*/
