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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(LinkedNodeMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::BeginFunction, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Freeing linked xmlNode without unlinking",
                       "Memory Management")) {}

  void checkBeginFunction(CheckerContext &Ctx) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &Ctx) const;

private:
  static const MemRegion *getVarRegionFromExpr(const Expr *E,
                                               CheckerContext &C);
};

const MemRegion *SAGenTestChecker::getVarRegionFromExpr(const Expr *E,
                                                        CheckerContext &C) {
  if (!E)
    return nullptr;

  const Expr *Ex = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Ex)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      const VarRegion *VR = C.getState()->getRegion(VD, C.getLocationContext());
      if (VR)
        return VR->getBaseRegion();
    }
  }
  return nullptr;
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &Ctx) const {
  const Decl *D = Ctx.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return;

  if (FD->getNameAsString() != "xmlAddChild")
    return;

  if (FD->getNumParams() < 2)
    return;

  const ParmVarDecl *CurParam = FD->getParamDecl(1);
  const VarRegion *VR =
      Ctx.getState()->getRegion(CurParam, Ctx.getLocationContext());
  if (!VR)
    return;

  ProgramStateRef State = Ctx.getState();
  State = State->set<LinkedNodeMap>(VR->getBaseRegion(), true);
  Ctx.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &Ctx) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  ProgramStateRef State = Ctx.getState();

  if (ExprHasName(OriginExpr, "xmlUnlinkNodeInternal", Ctx)) {
    if (Call.getNumArgs() < 1)
      return;

    const MemRegion *MR = getVarRegionFromExpr(Call.getArgExpr(0), Ctx);
    if (!MR)
      return;

    const bool *Linked = State->get<LinkedNodeMap>(MR);
    if (Linked && *Linked) {
      State = State->set<LinkedNodeMap>(MR, false);
      Ctx.addTransition(State);
    }
    return;
  }

  if (ExprHasName(OriginExpr, "xmlFreeNode", Ctx)) {
    if (Call.getNumArgs() < 1)
      return;

    const MemRegion *MR = getVarRegionFromExpr(Call.getArgExpr(0), Ctx);
    if (!MR)
      return;

    const bool *Linked = State->get<LinkedNodeMap>(MR);
    if (Linked && *Linked) {
      ExplodedNode *N = Ctx.generateNonFatalErrorNode();
      if (!N)
        return;

      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Freeing linked xmlNode without unlinking", N);
      Report->addRange(Call.getSourceRange());
      Ctx.emitReport(std::move(Report));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing a linked xmlNode without unlinking it first",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
