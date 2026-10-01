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

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(AllocatedRegions, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall,
                                         check::PreCall,
                                         check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory leak", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                 CheckerContext &C) const;

private:
  void reportMemoryLeak(const Stmt *S, CheckerContext &C) const;
};

} // end anonymous namespace

static bool isAllocator(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, "xmlMalloc", C) ||
         ExprHasName(E, "malloc", C) ||
         ExprHasName(E, "calloc", C) ||
         ExprHasName(E, "realloc", C);
}

static bool isDeallocator(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, "xmlFree", C) ||
         ExprHasName(E, "free", C);
}

static bool isRealloc(const CallEvent &Call, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, "realloc", C);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  bool Changed = false;

  if (isAllocator(Call, C)) {
    const Expr *E = Call.getOriginExpr();
    const CallExpr *CE = dyn_cast_or_null<CallExpr>(E);
    if (!CE)
      return;

    // For realloc, the old pointer is freed.
    if (isRealloc(Call, C) && Call.getNumArgs() > 0) {
      SVal OldArg = Call.getArgSVal(0);
      const MemRegion *OldMR = OldArg.getAsRegion();
      if (OldMR) {
        OldMR = OldMR->getBaseRegion();
        State = State->set<AllocatedRegions>(OldMR, false);
        Changed = true;
      }
    }

    const MemRegion *MR = Call.getReturnValue().getAsRegion();
    if (!MR) {
      SValBuilder &SVB = C.getSValBuilder();
      const LocationContext *LCtx = C.getLocationContext();
      unsigned Count = C.blockCount();
      DefinedSVal RetVal =
          SVB.getConjuredHeapSymbolVal(CE, LCtx, Count).castAs<DefinedSVal>();
      State = State->BindExpr(CE, LCtx, RetVal);
      MR = RetVal.getAsRegion();
    }

    if (MR) {
      MR = MR->getBaseRegion();
      State = State->set<AllocatedRegions>(MR, true);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isDeallocator(Call, C))
    return;

  ProgramStateRef State = C.getState();
  if (Call.getNumArgs() < 1)
    return;

  SVal Arg = Call.getArgSVal(0);
  const MemRegion *MR = Arg.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  const bool *Owned = State->get<AllocatedRegions>(MR);
  if (Owned && *Owned) {
    State = State->set<AllocatedRegions>(MR, false);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // General case: overwriting an owned pointer with a new allocation.
  const MemRegion *LocReg = Loc.getAsRegion();
  if (LocReg) {
    LocReg = LocReg->getBaseRegion();
    const bool *OldOwned = State->get<AllocatedRegions>(LocReg);
    if (OldOwned && *OldOwned) {
      const MemRegion *NewReg = Val.getAsRegion();
      if (NewReg) {
        NewReg = NewReg->getBaseRegion();
        const bool *NewOwned = State->get<AllocatedRegions>(NewReg);
        if (NewOwned && *NewOwned) {
          reportMemoryLeak(StoreE, C);
          return;
        }
      }
    }
  }

  // Special case for xmlCtxtSetSaxHandler.
  const StackFrameContext *SF = C.getStackFrame();
  if (!SF)
    return;

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(SF->getDecl());
  if (!FD || FD->getNameAsString() != "xmlCtxtSetSaxHandler")
    return;

  const BinaryOperator *BO = dyn_cast_or_null<BinaryOperator>(StoreE);
  if (!BO || BO->getOpcode() != BO_Assign)
    return;

  const Expr *LHS = BO->getLHS();
  if (!ExprHasName(LHS, "ctxt->sax", C))
    return;

  const MemRegion *NewReg = Val.getAsRegion();
  if (!NewReg)
    return;

  NewReg = NewReg->getBaseRegion();
  const bool *NewOwned = State->get<AllocatedRegions>(NewReg);
  if (NewOwned && *NewOwned) {
    reportMemoryLeak(StoreE, C);
  }
}

void SAGenTestChecker::reportMemoryLeak(const Stmt *S,
                                        CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Memory leak: overwriting owned pointer without freeing old value", N);
  if (S)
    Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memory leaks when overwriting an owned heap pointer without freeing it",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
