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
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Track local automatic variables that have been declared without an
// initializer and have not yet been assigned on the current path.
REGISTER_SET_WITH_PROGRAMSTATE(UninitVars, const VarDecl *)

namespace {
class SAGenTestChecker : public Checker<check::PreStmt<DeclStmt>,
                                        check::Bind,
                                        check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use of uninitialized variable",
                       "Uninitialized variable")) {}

  void checkPreStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPreStmt(const DeclStmt *DS,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (const Decl *D : DS->decls()) {
    const VarDecl *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    // Only track local automatic variables.
    if (!VD->hasLocalStorage())
      continue;

    if (!VD->hasInit()) {
      if (!State->contains<UninitVars>(VD)) {
        State = State->add<UninitVars>(VD);
        Changed = true;
      }
    } else {
      if (State->contains<UninitVars>(VD)) {
        State = State->remove<UninitVars>(VD);
        Changed = true;
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;

  const VarDecl *VD = VR->getDecl();
  if (!VD)
    return;

  if (State->contains<UninitVars>(VD)) {
    State = State->remove<UninitVars>(VD);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;

  const VarDecl *VD = VR->getDecl();
  if (!VD)
    return;

  if (!State->contains<UninitVars>(VD))
    return;

  // Remove the variable so that we don't report multiple times on the same path.
  State = State->remove<UninitVars>(VD);

  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;

  std::string Msg = "Use of uninitialized variable '";
  Msg += VD->getNameAsString();
  Msg += "'";

  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    Report->addRange(S->getSourceRange());

  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of uninitialized automatic local variables",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
