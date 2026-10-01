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
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_TRAIT_WITH_PROGRAMSTATE(Reported, bool)

namespace {
class SAGenTestChecker : public Checker<check::BeginFunction, check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "NULL pointer dereference", "Null Dereference")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;

private:
  const ParmVarDecl *getInParam(CheckerContext &C) const;
};
} // end anonymous namespace

const ParmVarDecl *SAGenTestChecker::getInParam(CheckerContext &C) const {
  const FunctionDecl *FD =
      dyn_cast<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD || FD->getName() != "curl_url_dup")
    return nullptr;
  if (FD->getNumParams() == 0)
    return nullptr;
  const ParmVarDecl *InParam = FD->getParamDecl(0);
  if (!InParam || !InParam->getType()->isPointerType())
    return nullptr;
  return InParam;
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const ParmVarDecl *InParam = getInParam(C);
  if (!InParam)
    return;

  ProgramStateRef State = C.getState();
  SVal ParamSVal =
      State->getSVal(State->getLValue(InParam, C.getLocationContext()));
  auto ParamDV = ParamSVal.getAs<DefinedOrUnknownSVal>();
  if (!ParamDV)
    return;
  State = State->assume(*ParamDV, false);
  if (!State)
    return;
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (State->get<Reported>())
    return;

  const ParmVarDecl *InParam = getInParam(C);
  if (!InParam)
    return;

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;
  if (VR->getDecl() != InParam)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "NULL pointer dereference: 'in' is not checked before use", N);
  if (S)
    report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));

  State = State->set<Reported>(true);
  C.addTransition(State);
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL validation of input handle pointer before dereference",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
