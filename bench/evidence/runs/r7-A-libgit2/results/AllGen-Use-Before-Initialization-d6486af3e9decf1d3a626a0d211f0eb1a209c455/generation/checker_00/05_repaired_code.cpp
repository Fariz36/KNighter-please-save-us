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
#include "clang/AST/DeclGroup.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include <optional>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks local variables that were declared without an initializer and have
// not yet been assigned on the current path.
REGISTER_SET_WITH_PROGRAMSTATE(UninitializedVars, const VarRegion *)

namespace {
class SAGenTestChecker : public Checker<check::PostStmt<DeclStmt>,
                                        check::Bind,
                                        check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use of uninitialized local variable",
                       "Uninitialized Value")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS,
                                     CheckerContext &C) const {
  if (!DS)
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (const Decl *D : DS->decls()) {
    const VarDecl *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    // Only track local, non-parameter variables without an initializer.
    // Static locals are zero-initialized by the language, so skip them.
    if (!VD->isLocalVarDecl() || VD->hasInit() || VD->isStaticLocal() ||
        isa<ParmVarDecl>(VD))
      continue;

    const VarRegion *VR = State->getRegion(VD, C.getLocationContext());
    if (!VR)
      continue;

    if (!State->contains<UninitializedVars>(VR)) {
      State = State->add<UninitializedVars>(VR);
      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  auto MRV = Loc.getAs<loc::MemRegionVal>();
  if (!MRV)
    return;

  const MemRegion *MR = MRV->getRegion();
  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;

  if (State->contains<UninitializedVars>(VR)) {
    State = State->remove<UninitializedVars>(VR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;

  ProgramStateRef State = C.getState();

  auto MRV = Loc.getAs<loc::MemRegionVal>();
  if (!MRV)
    return;

  const MemRegion *MR = MRV->getRegion();
  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;

  if (!State->contains<UninitializedVars>(VR))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  StringRef Name = VR->getDecl()->getName();
  std::string Msg = "Use of uninitialized local variable '";
  Msg += Name.str();
  Msg += "'";

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    R->addRange(S->getSourceRange());
  C.emitReport(std::move(R));

  // Avoid duplicate warnings on the same path.
  State = State->remove<UninitializedVars>(VR);
  C.addTransition(State);
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of uninitialized local variables",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
