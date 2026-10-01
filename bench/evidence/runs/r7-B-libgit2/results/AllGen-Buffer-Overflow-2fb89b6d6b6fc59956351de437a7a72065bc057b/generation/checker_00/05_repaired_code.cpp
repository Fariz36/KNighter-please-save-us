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
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Map pointer variables' storage regions to a flag indicating that they point
// into a length-delimited buffer.
REGISTER_MAP_WITH_PROGRAMSTATE(BoundedPtrMap, const MemRegion *, bool)

namespace {

// Returns true if E is a call to memchr(), memmem(), or memrchr().
static bool isBoundedSource(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  if (const CallExpr *CE = dyn_cast<CallExpr>(E)) {
    return ExprHasName(CE, "memchr", C) ||
           ExprHasName(CE, "memmem", C) ||
           ExprHasName(CE, "memrchr", C);
  }
  return false;
}

// Returns true if E is known to be a pointer into a length-delimited buffer.
static bool isBoundedPtr(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  // A pointer variable whose storage region has been marked as bounded.
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return false;

    ProgramStateRef State = C.getState();

    // Check the variable's storage region.
    const MemRegion *Storage =
        State->getLValue(VD, C.getLocationContext()).getAsRegion();
    if (Storage) {
      Storage = Storage->getBaseRegion();
      if (const bool *B = State->get<BoundedPtrMap>(Storage)) {
        if (*B)
          return true;
      }
    }

    // Also check the value region. This helps when the buffer itself was
    // marked by the optional safety net for memchr()/memmem()/memrchr().
    const MemRegion *ValReg =
        State->getSVal(E, C.getLocationContext()).getAsRegion();
    if (ValReg) {
      ValReg = ValReg->getBaseRegion();
      if (const bool *B = State->get<BoundedPtrMap>(ValReg)) {
        if (*B)
          return true;
      }
    }

    return false;
  }

  // Pointer arithmetic preserves boundedness.
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Add || BO->getOpcode() == BO_Sub) {
      return isBoundedPtr(BO->getLHS(), C) ||
             isBoundedPtr(BO->getRHS(), C);
    }
  }

  // strstr()/strchr() return a pointer into their first argument.
  if (const CallExpr *CE = dyn_cast<CallExpr>(E)) {
    if (ExprHasName(CE, "strstr", C) || ExprHasName(CE, "strchr", C)) {
      if (CE->getNumArgs() > 0)
        return isBoundedPtr(CE->getArg(0), C);
    }
  }

  return false;
}

class SAGenTestChecker : public Checker<check::Bind, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unbounded String Search", "Memory Safety")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S,
                 CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call,
                    CheckerContext &C) const;
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *Dest = Loc.getAsRegion();
  if (!Dest)
    return;
  Dest = Dest->getBaseRegion();
  if (!Dest)
    return;

  const Expr *RHS = nullptr;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign)
      RHS = BO->getRHS();
  } else if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    for (auto I = DS->decl_begin(), E = DS->decl_end(); I != E; ++I) {
      const VarDecl *VD = dyn_cast<VarDecl>(*I);
      if (!VD || !VD->hasInit())
        continue;

      const MemRegion *VDReg =
          State->getLValue(VD, C.getLocationContext()).getAsRegion();
      if (VDReg && VDReg->getBaseRegion() == Dest) {
        RHS = VD->getInit();
        break;
      }
    }
  }

  if (!RHS)
    return;

  if (isBoundedSource(RHS, C) || isBoundedPtr(RHS, C)) {
    State = State->set<BoundedPtrMap>(Dest, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Optional safety net: mark buffers passed to bounded search functions.
  if (ExprHasName(OriginExpr, "memchr", C) ||
      ExprHasName(OriginExpr, "memmem", C) ||
      ExprHasName(OriginExpr, "memrchr", C)) {
    if (Call.getNumArgs() > 0) {
      const Expr *Arg0 = Call.getArgExpr(0);
      if (Arg0) {
        const MemRegion *MR = getMemRegionFromExpr(Arg0, C);
        if (MR) {
          MR = MR->getBaseRegion();
          State = State->set<BoundedPtrMap>(MR, true);
          C.addTransition(State);
        }
      }
    }
    return;
  }

  // Detect unbounded search functions.
  if (!(ExprHasName(OriginExpr, "strstr", C) ||
        ExprHasName(OriginExpr, "strchr", C)))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *Arg0 = Call.getArgExpr(0);
  if (!Arg0)
    return;

  if (isBoundedPtr(Arg0, C)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Unbounded string search on length-delimited buffer; may read out of "
        "bounds. Use bounded search or ensure NUL-termination.",
        N);
    report->addRange(Call.getSourceRange());
    C.emitReport(std::move(report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded strstr/strchr on length-delimited buffers",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
