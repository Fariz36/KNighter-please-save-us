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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/OperationKinds.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Casting.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UninitVars, const MemRegion *, bool)

namespace {
class SAGenTestChecker : public Checker<check::PostStmt<DeclStmt>,
                                        check::Bind,
                                        check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Uninitialized local variable",
                       "Uninitialized Value")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  for (const Decl *D : DS->decls()) {
    const VarDecl *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    // Only consider local variables that are not static and have no initializer.
    if (!VD->hasLocalStorage() || VD->isStaticLocal())
      continue;
    if (VD->hasInit())
      continue;

    const MemRegion *R = State->getLValue(VD, C.getLocationContext()).getAsRegion();
    if (!R)
      continue;

    State = State->set<UninitVars>(R, true);
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  // If the region is tracked as uninitialized, mark it as initialized.
  const bool *Uninit = State->get<UninitVars>(R);
  if (Uninit && *Uninit) {
    State = State->set<UninitVars>(R, false);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  R = R->getBaseRegion();
  const bool *Uninit = State->get<UninitVars>(R);
  if (!Uninit || !*Uninit)
    return;

  // Check if the load occurs as an operand of a logical AND or OR.
  const BinaryOperator *BO = findSpecificTypeInParents<BinaryOperator>(S, C);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_LAnd && Op != BO_LOr)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  std::string VarName;
  if (const VarRegion *VR = dyn_cast<VarRegion>(R))
    VarName = VR->getDecl()->getName().str();

  std::string Msg = "Use of uninitialized local variable";
  if (!VarName.empty())
    Msg += " '" + VarName + "'";
  Msg += " in logical expression";

  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of uninitialized local variables in logical expressions",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
