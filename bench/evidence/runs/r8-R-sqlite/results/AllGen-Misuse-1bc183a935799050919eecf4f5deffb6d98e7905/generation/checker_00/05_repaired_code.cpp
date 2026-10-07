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
#include "knighter/roles.h"

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track token-type variables that have already been compared against the
// illegal-token sentinel on the current path.
REGISTER_SET_WITH_PROGRAMSTATE(CheckedTokenRegions, const MemRegion *)

namespace {
class SAGenTestChecker : public Checker<check::BranchCondition,
                                        check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Dequote Without Illegal Token Check",
                       "Token Handling")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};
} // end anonymous namespace

// Return the VarDecl referenced by E, if E is a simple reference to a variable.
static const VarDecl *getVarDecl(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      return VD;
  }
  return nullptr;
}

// Return true if E names the illegal-token sentinel role.
static bool isIllegalTokenSentinel(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *ND = dyn_cast<NamedDecl>(DRE->getDecl())) {
      return knighter::isRole("illegal_token_sentinel", ND->getName());
    }
  }
  return false;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const auto *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  Cond = Cond->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return;

  BinaryOperatorKind Op = BO->getOpcode();
  if (Op != BO_EQ && Op != BO_NE)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  const VarDecl *VD = nullptr;
  if (isIllegalTokenSentinel(LHS)) {
    VD = getVarDecl(RHS);
  } else if (isIllegalTokenSentinel(RHS)) {
    VD = getVarDecl(LHS);
  }

  if (!VD)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR =
      State->getLValue(VD, C.getLocationContext()).getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  State = State->add<CheckedTokenRegions>(MR);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "dequote"))
    return;

  const auto *FD = dyn_cast<FunctionDecl>(
      C.getCurrentAnalysisDeclContext()->getDecl());
  if (!FD || !knighter::declIsRole(FD, "dequote_compare"))
    return;

  ProgramStateRef State = C.getState();
  for (const ParmVarDecl *P : FD->parameters()) {
    const MemRegion *MR =
        State->getLValue(P, C.getLocationContext()).getAsRegion();
    if (!MR)
      continue;

    MR = MR->getBaseRegion();
    if (State->contains<CheckedTokenRegions>(MR))
      return;
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Dequote without illegal-token check", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dequote routines invoked without prior illegal-token check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "illegal_token_sentinel": {"names": ["TK_ILLEGAL"], "description": "token type value indicating an invalid or illegal token; must be rejected before dequoting"},
  "dequote": {"names": ["sqlite3Dequote"], "description": "dequote/normalizer routine that assumes its input is a syntactically valid quoted token"},
  "dequote_compare": {"names": ["quotedCompare"], "description": "wrapper that dequotes a token and compares it; must check the token type against the illegal sentinel before dequoting"}
}
*/
