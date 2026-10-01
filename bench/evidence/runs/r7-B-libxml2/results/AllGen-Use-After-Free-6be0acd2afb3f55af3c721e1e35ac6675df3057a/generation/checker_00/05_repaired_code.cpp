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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UnlinkedNodes, const MemRegion *, bool)

namespace {

static bool isCallTo(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, Name, C);
}

static bool isXmlAddChild(CheckerContext &C) {
  const AnalysisDeclContext *ADC = C.getCurrentAnalysisDeclContext();
  if (!ADC)
    return false;
  const Decl *D = ADC->getDecl();
  if (!D)
    return false;
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  return FD && FD->getNameAsString() == "xmlAddChild";
}

static bool isCurArg(const Expr *Arg) {
  if (!Arg)
    return false;
  const Expr *E = Arg->IgnoreImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return false;
  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  return PVD && PVD->getName() == "cur";
}

static const MemRegion *getNodeRegion(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;

  // Try the utility first; this works when the pointer evaluates to a
  // concrete MemRegion.
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (MR)
    return MR->getBaseRegion();

  // Fallback for symbolic pointers, such as function parameters.
  SVal V = C.getState()->getSVal(E, C.getLocationContext());
  MR = V.getAsRegion();
  if (MR)
    return MR->getBaseRegion();

  return nullptr;
}

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Freeing linked node without unlinking it first",
                       "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isCallTo(Call, "xmlUnlinkNodeInternal", C)) {
    if (Call.getNumArgs() < 1)
      return;
    const Expr *Arg = Call.getArgExpr(0);
    const MemRegion *MR = getNodeRegion(Arg, C);
    if (!MR)
      return;
    State = State->set<UnlinkedNodes>(MR, true);
    C.addTransition(State);
    return;
  }

  if (isCallTo(Call, "xmlFreeNode", C)) {
    if (!isXmlAddChild(C))
      return;
    if (Call.getNumArgs() < 1)
      return;
    const Expr *Arg = Call.getArgExpr(0);
    if (!isCurArg(Arg))
      return;

    const MemRegion *MR = getNodeRegion(Arg, C);
    if (!MR)
      return;

    const bool *Unlinked = State->get<UnlinkedNodes>(MR);
    if (Unlinked && *Unlinked)
      return;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Freeing linked node without unlinking it first", N);
    report->addRange(Call.getSourceRange());
    C.emitReport(std::move(report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects xmlFreeNode(cur) in xmlAddChild without xmlUnlinkNodeInternal(cur)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
