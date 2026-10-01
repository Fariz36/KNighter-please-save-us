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
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks whether blob->data has been NULL-checked in the current path
// while analyzing Curl_setblobopt.
REGISTER_TRAIT_WITH_PROGRAMSTATE(BlobDataChecked, bool)

namespace {

class SAGenTestChecker : public Checker<
    check::BeginFunction,
    check::BranchCondition,
    check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL check for blob->data",
                       "Null Pointer")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
};

} // end anonymous namespace

// Helper: check if the current function being analyzed is Curl_setblobopt.
static bool isCurlSetblobopt(CheckerContext &C) {
  const Decl *D = C.getLocationContext()->getDecl();
  const auto *FD = dyn_cast<FunctionDecl>(D);
  return FD && FD->getName() == "Curl_setblobopt";
}

// Helper: check if an expression is a dereference of a parameter with the
// given name, e.g. `*blob` where `blob` is a parameter.
static bool isDerefOfParam(const Expr *E, StringRef ParamName,
                           CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          return VD->getName() == ParamName;
        }
      }
    }
  }

  return false;
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  if (!isCurlSetblobopt(C))
    return;

  ProgramStateRef State = C.getState();
  State = State->set<BlobDataChecked>(false);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!isCurlSetblobopt(C))
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  // If the condition checks blob->data (e.g. !blob->data, blob->data == NULL),
  // mark it as checked for the remainder of this path.
  if (ExprHasName(CondE, "blob->data", C)) {
    ProgramStateRef State = C.getState();
    State = State->set<BlobDataChecked>(true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO,
                                    CheckerContext &C) const {
  if (!isCurlSetblobopt(C))
    return;

  if (!BO->isAssignmentOp())
    return;

  ProgramStateRef State = C.getState();
  if (State->get<BlobDataChecked>())
    return;

  // Detect assignments like `*nblob = *blob`, where the blob struct (and thus
  // blob->data) is copied without a prior NULL check on blob->data.
  const Expr *RHS = BO->getRHS();
  if (isDerefOfParam(RHS, "blob", C)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "blob->data may be NULL and is used without NULL check", N);
    report->addRange(BO->getSourceRange());
    C.emitReport(std::move(report));
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL check for blob->data in Curl_setblobopt",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
