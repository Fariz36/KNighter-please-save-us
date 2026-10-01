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
#include "clang/AST/Stmt.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UninitVars, const VarDecl *, bool)

namespace {
class SAGenTestChecker : public Checker<check::PostStmt<DeclStmt>,
                                         check::Bind,
                                         check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Uninitialized Local Variable",
                       "Uninitialized")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                 CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;

private:
  void reportUninitRead(const VarDecl *VD, const Stmt *S,
                        CheckerContext &C) const;
};
} // namespace

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS,
                                     CheckerContext &C) const {
  if (!DS)
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    if (isa<ParmVarDecl>(VD) || !VD->hasLocalStorage())
      continue;

    bool IsUninit = !VD->hasInit();
    State = State->set<UninitVars>(VD, IsUninit);
    Changed = true;
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  const auto *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;

  const VarDecl *VD = VR->getDecl();
  const bool *Uninit = State->get<UninitVars>(VD);
  if (!Uninit || !*Uninit)
    return;

  State = State->set<UninitVars>(VD, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  const auto *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;

  const VarDecl *VD = VR->getDecl();
  const bool *Uninit = C.getState()->get<UninitVars>(VD);
  if (!Uninit || !*Uninit)
    return;

  reportUninitRead(VD, S, C);
}

void SAGenTestChecker::reportUninitRead(const VarDecl *VD, const Stmt *S,
                                        CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  std::string Msg = "Use of uninitialized local variable '" +
                    VD->getNameAsString() + "'";
  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects reads of uninitialized local automatic variables",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
