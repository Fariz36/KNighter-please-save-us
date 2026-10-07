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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(SourceCheckedMap, const MemRegion *, bool)

namespace {

static const MemRegion *getVarRegion(const ParmVarDecl *P, CheckerContext &C) {
  return C.getState()->getLValue(P, C.getLocationContext()).getAsRegion();
}

static bool isParamRef(const Expr *E, const ParmVarDecl *P) {
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == P;
  }
  return false;
}

static bool isNullCheckForParam(const Expr *Cond, const ParmVarDecl *P,
                                bool &NullBranchIsTrue, CheckerContext &C) {
  Cond = Cond->IgnoreParenImpCasts();
  ASTContext &AC = C.getASTContext();

  // !P
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      if (isParamRef(UO->getSubExpr(), P)) {
        NullBranchIsTrue = true;
        return true;
      }
    }
  }

  // P == NULL, P != NULL
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LHSIsP = isParamRef(LHS, P);
      bool RHSIsP = isParamRef(RHS, P);
      bool LHSIsNull = LHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);

      if (LHSIsP && RHSIsNull) {
        NullBranchIsTrue = (BO->getOpcode() == BO_EQ);
        return true;
      }
      if (RHSIsP && LHSIsNull) {
        NullBranchIsTrue = (BO->getOpcode() == BO_EQ);
        return true;
      }
    }
  }

  // P as condition
  if (isParamRef(Cond, P)) {
    NullBranchIsTrue = false; // true means non-null, false means null
    return true;
  }

  return false;
}

static bool branchExits(const Stmt *S) {
  if (!S)
    return false;
  if (isa<ReturnStmt>(S))
    return true;
  if (isa<GotoStmt>(S))
    return true;
  if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
    if (CS->body_empty())
      return false;
    return branchExits(CS->body_back());
  }
  return false;
}

class SAGenTestChecker : public Checker<check::BeginFunction,
                                         check::BranchCondition,
                                         check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "NULL source handle dereference",
                       "Null Pointer")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD || !knighter::declIsRole(FD, "duplicator"))
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;
  for (const ParmVarDecl *P : FD->parameters()) {
    if (!knighter::declIsRole(P, "source_handle"))
      continue;
    const MemRegion *R = getVarRegion(P, C);
    if (!R)
      continue;
    State = State->set<SourceCheckedMap>(R, false);
    Changed = true;
  }
  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD || !knighter::declIsRole(FD, "duplicator"))
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;
  for (const ParmVarDecl *P : FD->parameters()) {
    if (!knighter::declIsRole(P, "source_handle"))
      continue;

    bool NullBranchIsTrue = false;
    if (!isNullCheckForParam(CondE, P, NullBranchIsTrue, C))
      continue;

    const Stmt *NullBranch = NullBranchIsTrue ? IS->getThen() : IS->getElse();
    if (!NullBranch)
      continue;
    if (!branchExits(NullBranch))
      continue;

    const MemRegion *R = getVarRegion(P, C);
    if (!R)
      continue;

    const bool *Checked = State->get<SourceCheckedMap>(R);
    if (Checked && *Checked)
      continue;

    State = State->set<SourceCheckedMap>(R, true);
    Changed = true;
  }
  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD || !knighter::declIsRole(FD, "duplicator"))
    return;

  const MemRegion *LocReg = Loc.getAsRegion();
  if (!LocReg)
    return;

  ProgramStateRef State = C.getState();
  for (const ParmVarDecl *P : FD->parameters()) {
    if (!knighter::declIsRole(P, "source_handle"))
      continue;

    const MemRegion *R = getVarRegion(P, C);
    if (!R)
      continue;

    const bool *Checked = State->get<SourceCheckedMap>(R);
    if (!Checked || *Checked)
      continue;

    SVal SourceVal = State->getSVal(State->getLValue(P, C.getLocationContext()));
    const MemRegion *Pointee = SourceVal.getAsRegion();
    if (!Pointee)
      continue;

    bool isDeref = false;
    const MemRegion *Super = LocReg;
    while (Super) {
      if (Super == Pointee) {
        isDeref = true;
        break;
      }
      const SubRegion *SR = dyn_cast<SubRegion>(Super);
      if (!SR)
        break;
      Super = SR->getSuperRegion();
    }
    if (!isDeref)
      continue;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      continue;

    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Dereference of NULL source handle before validation", N);
    if (S)
      report->addRange(S->getSourceRange());
    C.emitReport(std::move(report));

    // Suppress duplicate reports on the same path.
    State = State->set<SourceCheckedMap>(R, true);
    C.addTransition(State);
    break; // Report once per source handle.
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects NULL dereference of source handle before validation in duplicator functions",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "duplicator": {
    "names": ["curl_url_dup"],
    "description": "function that duplicates a source handle into a newly allocated destination"
  },
  "source_handle": {
    "names": ["in"],
    "description": "parameter of a duplicator that points to the source object; may be NULL"
  },
  "destination_allocator": {
    "names": ["curlx_calloc"],
    "description": "allocator used to allocate the destination handle in a duplicator"
  },
  "field_copier": {
    "names": ["DUP"],
    "description": "macro/operation that copies fields from the source handle, dereferencing the source pointer"
  }
}
*/
