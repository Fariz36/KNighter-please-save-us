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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks whether a local variable has definitely been initialized.
// Missing entry or false means the variable is still uninitialized.
REGISTER_MAP_WITH_PROGRAMSTATE(InitializedVars, const VarDecl *, bool)

namespace {

class SAGenTestChecker
    : public Checker<check::PostStmt<DeclStmt>,
                     check::Bind,
                     check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Uninitialized variable", "Memory Error")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;

private:
  void reportUse(const VarDecl *VD, const Stmt *S, CheckerContext &C) const;
};

static bool isTrackableLocalVar(const VarDecl *VD) {
  if (!VD)
    return false;
  if (!VD->isLocalVarDecl())
    return false;
  if (isa<ParmVarDecl>(VD))
    return false;
  if (VD->isStaticLocal())
    return false;
  return true;
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS,
                                     CheckerContext &C) const {
  if (!DS)
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (const Decl *D : DS->decls()) {
    const VarDecl *VD = dyn_cast<VarDecl>(D);
    if (!VD || !isTrackableLocalVar(VD))
      continue;

    if (VD->hasInit()) {
      const bool *Init = State->get<InitializedVars>(VD);
      if (!Init || !*Init) {
        State = State->set<InitializedVars>(VD, true);
        Changed = true;
      }
    } else {
      // Reset to uninitialized. This is important for declarations
      // inside loops, where each iteration starts fresh.
      if (State->get<InitializedVars>(VD)) {
        State = State->remove<InitializedVars>(VD);
        Changed = true;
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;

  const VarDecl *VD = VR->getDecl();
  if (!isTrackableLocalVar(VD))
    return;

  ProgramStateRef State = C.getState();
  const bool *Init = State->get<InitializedVars>(VD);
  if (!Init || !*Init) {
    State = State->set<InitializedVars>(VD, true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;

  const VarDecl *VD = VR->getDecl();
  if (!isTrackableLocalVar(VD))
    return;

  ProgramStateRef State = C.getState();
  const bool *Init = State->get<InitializedVars>(VD);
  if (!Init || !*Init) {
    reportUse(VD, S, C);
  }
}

void SAGenTestChecker::reportUse(const VarDecl *VD, const Stmt *S,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  std::string Msg =
      "Use of uninitialized variable '" + VD->getNameAsString() + "'";
  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of uninitialized local variables",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
