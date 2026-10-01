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
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Map from node memory regions to whether they have been unlinked.
REGISTER_MAP_WITH_PROGRAMSTATE(UnlinkedNodes, const MemRegion *, bool)

namespace {
class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing xmlUnlinkNodeInternal before xmlFreeNode",
                       "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportMissingUnlink(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *CalleeExpr = Call.getOriginExpr();
  if (!CalleeExpr)
    return;

  ProgramStateRef State = C.getState();

  // ------------------------------------------------------------------
  // xmlUnlinkNodeInternal(node): remember that this node has been unlinked.
  // ------------------------------------------------------------------
  if (ExprHasName(CalleeExpr, "xmlUnlinkNodeInternal", C)) {
    const Expr *ArgExpr = Call.getArgExpr(0);
    if (!ArgExpr)
      return;

    const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();

    State = State->set<UnlinkedNodes>(MR, true);
    C.addTransition(State);
    return;
  }

  // ------------------------------------------------------------------
  // xmlFreeNode(cur): in xmlAddChild's XML_TEXT_NODE branch, check that
  // xmlUnlinkNodeInternal(cur) was called first.
  // ------------------------------------------------------------------
  if (!ExprHasName(CalleeExpr, "xmlFreeNode", C))
    return;

  // Must be inside xmlAddChild.
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return;

  const Decl *D = LCtx->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || FD->getName() != "xmlAddChild")
    return;

  // The freed pointer must be the second parameter: cur.
  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;

  const Expr *Arg = ArgExpr->IgnoreImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Arg);
  if (!DRE)
    return;

  if (FD->getNumParams() < 2)
    return;

  const ParmVarDecl *CurParam = FD->getParamDecl(1);
  if (!CurParam || DRE->getDecl() != CurParam)
    return;

  // Must be in the XML_TEXT_NODE branch.
  const IfStmt *EnclosingIf =
      findSpecificTypeInParents<IfStmt>(CalleeExpr, C);
  if (!EnclosingIf)
    return;

  const Expr *Cond = EnclosingIf->getCond();
  if (!Cond || !ExprHasName(Cond, "XML_TEXT_NODE", C))
    return;

  // Get the node region being freed.
  const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();

  // If we have already recorded an unlink for this exact node, it is safe.
  const bool *Unlinked = State->get<UnlinkedNodes>(MR);
  if (Unlinked && *Unlinked)
    return;

  reportMissingUnlink(Call, C);
}

void SAGenTestChecker::reportMissingUnlink(const CallEvent &Call,
                                           CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing xmlUnlinkNodeInternal before xmlFreeNode", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects xmlFreeNode called without xmlUnlinkNodeInternal in xmlAddChild",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
