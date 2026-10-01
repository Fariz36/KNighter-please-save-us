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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Track variables that hold pointers derived from memchr (or from unbounded
// string functions applied to such pointers).
REGISTER_MAP_WITH_PROGRAMSTATE(MemchrPtrMap, const MemRegion *, bool)

namespace {

static bool isUnboundedStringFunc(StringRef Name) {
  return Name == "strstr" || Name == "strchr" || Name == "strrchr" ||
         Name == "strpbrk";
}

static bool isMemchrCall(const Expr *E) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  const CallExpr *CE = dyn_cast<CallExpr>(E);
  if (!CE)
    return false;

  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return false;

  return FD->getName() == "memchr";
}

static const MemRegion *getVarRegion(const DeclRefExpr *DRE,
                                     CheckerContext &C) {
  if (!DRE)
    return nullptr;

  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return nullptr;

  const MemRegion *MR =
      C.getState()->getLValue(VD, C.getLocationContext()).getAsRegion();
  if (!MR)
    return nullptr;

  return MR->getBaseRegion();
}

static bool isDerivedFromMemchr(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (isMemchrCall(E))
    return true;

  if (const CallExpr *CE = dyn_cast<CallExpr>(E)) {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD)
      return false;

    if (isUnboundedStringFunc(FD->getName())) {
      if (CE->getNumArgs() > 0)
        return isDerivedFromMemchr(CE->getArg(0), C);
    }
    return false;
  }

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    const MemRegion *MR = getVarRegion(DRE, C);
    if (!MR)
      return false;

    const bool *Flag = C.getState()->get<MemchrPtrMap>(MR);
    return Flag && *Flag;
  }

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E))
    return isDerivedFromMemchr(UO->getSubExpr(), C);

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->isAssignmentOp())
      return isDerivedFromMemchr(BO->getRHS(), C);

    return isDerivedFromMemchr(BO->getLHS(), C) ||
           isDerivedFromMemchr(BO->getRHS(), C);
  }

  if (const CastExpr *CE = dyn_cast<CastExpr>(E))
    return isDerivedFromMemchr(CE->getSubExpr(), C);

  return false;
}

class SAGenTestChecker
    : public Checker<check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Unbounded string function on length-delimited buffer",
                       "Memory Safety")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  void reportBug(const Expr *Arg, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  const CallExpr *CE = dyn_cast<CallExpr>(Origin);
  if (!CE)
    return;

  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return;

  if (!isUnboundedStringFunc(FD->getName()))
    return;

  if (CE->getNumArgs() < 1)
    return;

  const Expr *Arg0 = CE->getArg(0);
  if (isMemchrCall(Arg0))
    return;

  if (isDerivedFromMemchr(Arg0, C))
    reportBug(Arg0, C);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  if (!isa<VarRegion>(MR))
    return;

  MR = MR->getBaseRegion();

  const Expr *BoundExpr = nullptr;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp())
      BoundExpr = BO->getRHS();
  } else if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    const VarRegion *VR = cast<VarRegion>(MR);
    const VarDecl *VD = VR->getDecl();
    if (VD)
      BoundExpr = VD->getInit();
  }

  if (!BoundExpr)
    return;

  if (isDerivedFromMemchr(BoundExpr, C)) {
    State = State->set<MemchrPtrMap>(MR, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::reportBug(const Expr *Arg, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unbounded string function on length-delimited buffer; use bounded search "
      "(memmem/memchr)",
      N);

  if (Arg)
    report->addRange(Arg->getSourceRange());

  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded string functions on pointers derived from memchr",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
