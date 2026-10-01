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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/SmallVector.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Map an owned SrcList pointer symbol to the statement that allocated/duplicated it.
REGISTER_MAP_WITH_PROGRAMSTATE(OwnedSrcListMap, SymbolRef, const Stmt *)

namespace {
class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::Bind,
                                        check::PreStmt<ReturnStmt>,
                                        check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "SrcList Leak", "Memory Leak")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  ProgramStateRef removeOwned(ProgramStateRef State, SymbolRef Sym) const;
};
} // end anonymous namespace

ProgramStateRef SAGenTestChecker::removeOwned(ProgramStateRef State,
                                              SymbolRef Sym) const {
  if (State->get<OwnedSrcListMap>(Sym))
    State = State->remove<OwnedSrcListMap>(Sym);
  return State;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return;

  if (!ExprHasName(E, "sqlite3SrcListDup", C) &&
      !ExprHasName(E, "sqlite3SrcListAppendFromTerm", C))
    return;

  SymbolRef Sym = Call.getReturnValue().getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<OwnedSrcListMap>(Sym, E);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return;

  ProgramStateRef State = C.getState();

  // sqlite3SrcListDelete(db, pList): the SrcList is freed.
  if (ExprHasName(E, "sqlite3SrcListDelete", C)) {
    if (Call.getNumArgs() > 1) {
      SVal Arg = Call.getArgSVal(1);
      if (SymbolRef Sym = Arg.getAsSymbol()) {
        State = removeOwned(State, Sym);
      }
    }
  }
  // sqlite3SrcListAppendList(pParse, p1, p2): p2 is consumed.
  // sqlite3SelectNew(..., pFromDup, ...): pFromDup is consumed.
  else if (ExprHasName(E, "sqlite3SrcListAppendList", C) ||
           ExprHasName(E, "sqlite3SelectNew", C)) {
    unsigned Idx = 2;
    if (Call.getNumArgs() > Idx) {
      SVal Arg = Call.getArgSVal(Idx);
      if (SymbolRef Sym = Arg.getAsSymbol()) {
        State = removeOwned(State, Sym);
      }
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  SymbolRef Sym = Val.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  if (!State->get<OwnedSrcListMap>(Sym))
    return;

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  bool ShouldRelease = false;
  if (isa<FieldRegion>(MR)) {
    ShouldRelease = true;
  } else if (const VarRegion *VR = dyn_cast<VarRegion>(MR)) {
    const VarDecl *VD = VR->getDecl();
    if (VD && !VD->isLocalVarDecl()) {
      ShouldRelease = true;
    }
  }

  if (ShouldRelease) {
    State = State->remove<OwnedSrcListMap>(Sym);
    C.addTransition(State);
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
  if (!Sym)
    return;

  if (State->get<OwnedSrcListMap>(Sym)) {
    State = State->remove<OwnedSrcListMap>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS,
                                        CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  auto M = State->get<OwnedSrcListMap>();

  llvm::SmallVector<std::pair<SymbolRef, const Stmt *>, 4> Leaked;
  for (auto I = M.begin(), E = M.end(); I != E; ++I) {
    Leaked.emplace_back(I->first, I->second);
  }

  for (auto &Entry : Leaked) {
    SymbolRef Sym = Entry.first;
    const Stmt *AllocStmt = Entry.second;

    // Only report if there is a feasible path where the pointer is non-null.
    DefinedSVal SymVal = C.getSValBuilder().makeSymbolVal(Sym);
    ProgramStateRef NonNullState = State->assume(SymVal, true);
    if (!NonNullState)
      continue;

    ExplodedNode *N = C.generateNonFatalErrorNode(NonNullState);
    if (!N)
      continue;

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Potential SrcList leak: missing cleanup on error path", N);
    if (AllocStmt)
      Report->addRange(AllocStmt->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects leaked SrcList allocations on error paths",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
