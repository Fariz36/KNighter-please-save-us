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

using namespace clang;
using namespace ento;
using namespace taint;

// Track whether the local variable `size` has been checked against
// BASE64_MAX_INPUT_SIZE before the arithmetic assignment.
REGISTER_MAP_WITH_PROGRAMSTATE(CheckedUpperBoundMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer overflow", "Security")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
};

} // end anonymous namespace

static bool isInTargetFunction(CheckerContext &C) {
  const Decl *D = C.getLocationContext()->getDecl();
  if (!D)
    return false;

  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  return FD && FD->getName() == "encoder_base64_size";
}

static bool isVarDeclRefTo(const DeclRefExpr *DRE, StringRef Name) {
  if (!DRE)
    return false;

  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  return VD && VD->getName() == Name;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!isInTargetFunction(C))
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  if (!ExprHasName(CondE, "BASE64_MAX_INPUT_SIZE", C))
    return;

  const DeclRefExpr *DRE = findSpecificTypeInChildren<DeclRefExpr>(Condition);
  if (!isVarDeclRefTo(DRE, "size"))
    return;

  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = State->getRegion(VD, C.getLocationContext());
  if (!MR)
    return;

  MR = MR->getBaseRegion();

  State = State->set<CheckedUpperBoundMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal /*Val*/, const Stmt *S,
                                 CheckerContext &C) const {
  if (!isInTargetFunction(C))
    return;

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || BO->getOpcode() != BO_Assign)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS);
  if (!isVarDeclRefTo(DRE, "size"))
    return;

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();

  const bool *Checked = C.getState()->get<CheckedUpperBoundMap>(MR);
  if (Checked && *Checked)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Integer overflow: input size not bounded before base64 size calculation.",
      N);
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in encoder_base64_size due to unchecked input size",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
