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
#include "clang/AST/ASTContext.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(OwnedVarMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::Bind, check::PreCall, check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory Leak", "Memory Management")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
};

} // end anonymous namespace

static bool isFunction(const CheckerContext &C, StringRef Name) {
  const LocationContext *LC = C.getLocationContext();
  if (!LC)
    return false;
  const Decl *D = LC->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  return FD && FD->getName() == Name;
}

static bool isDeclRefToVar(const Expr *E, StringRef Name) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return false;
  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  return VD && VD->getName() == Name;
}

static bool isCallTo(const Expr *E, StringRef Name) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  const CallExpr *CE = dyn_cast<CallExpr>(E);
  if (!CE)
    return false;
  const FunctionDecl *FD = CE->getDirectCallee();
  return FD && FD->getName() == Name;
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  if (!isFunction(C, "sqlite3TriggerUpdateStep"))
    return;

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;

  const VarDecl *VD = VR->getDecl();
  if (!VD || VD->getName() != "pFromDup")
    return;

  ProgramStateRef State = C.getState();
  bool Owned = false;

  const Expr *RHS = nullptr;
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      RHS = BO->getRHS();
    }
  } else if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    RHS = VD->getInit();
  }

  if (RHS) {
    RHS = RHS->IgnoreParenImpCasts();
    if (isCallTo(RHS, "sqlite3SrcListDup") ||
        isCallTo(RHS, "sqlite3SrcListAppendFromTerm") ||
        isDeclRefToVar(RHS, "pFrom")) {
      Owned = true;
    }
  }

  if (Owned) {
    State = State->set<OwnedVarMap>(VR, true);
  } else {
    State = State->remove<OwnedVarMap>(VR);
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isFunction(C, "sqlite3TriggerUpdateStep"))
    return;

  const IdentifierInfo *ID = Call.getCalleeIdentifier();
  if (!ID)
    return;

  StringRef Name = ID->getName();
  if (Name != "sqlite3SrcListDelete" && Name != "sqlite3SrcListAppendList")
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *Arg = Call.getArgExpr(i);
    if (isDeclRefToVar(Arg, "pFromDup")) {
      const DeclRefExpr *DRE =
          dyn_cast<DeclRefExpr>(Arg->IgnoreParenImpCasts());
      if (!DRE)
        continue;
      const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
      if (!VD)
        continue;

      SVal VarLoc = State->getLValue(VD, C.getLocationContext());
      const MemRegion *VR = VarLoc.getAsRegion();
      if (VR) {
        State = State->remove<OwnedVarMap>(VR);
        Changed = true;
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS,
                                        CheckerContext &C) const {
  if (!isFunction(C, "sqlite3TriggerUpdateStep"))
    return;

  ProgramStateRef State = C.getState();
  const OwnedVarMapTy &Map = State->get<OwnedVarMap>();
  if (Map.isEmpty())
    return;

  for (auto I = Map.begin(); I != Map.end(); ++I) {
    const MemRegion *VR = I->first;
    bool Owned = I->second;
    if (!Owned)
      continue;

    SVal Val = State->getSVal(VR);
    if (Val.isUnknown())
      continue;

    // Skip if the pointer is definitely null.
    if (State->isNull(Val).isConstrainedTrue())
      continue;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      continue;

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Memory leak: pFromDup is not freed", N);
    if (RS)
      Report->addRange(RS->getSourceRange());
    C.emitReport(std::move(Report));
    break;
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memory leaks of pFromDup in sqlite3TriggerUpdateStep",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
