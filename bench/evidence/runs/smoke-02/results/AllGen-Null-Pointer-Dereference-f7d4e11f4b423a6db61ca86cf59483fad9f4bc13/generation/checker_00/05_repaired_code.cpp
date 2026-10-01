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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool containsMemberAccess(const Stmt *S, StringRef FieldName,
                                 StringRef BaseName) {
  if (!S)
    return false;

  if (const auto *ME = dyn_cast<MemberExpr>(S)) {
    const ValueDecl *Member = ME->getMemberDecl();
    if (Member && Member->getNameAsString() == FieldName.str()) {
      const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
        if (DRE->getDecl() &&
            DRE->getDecl()->getNameAsString() == BaseName.str()) {
          return true;
        }
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (containsMemberAccess(Child, FieldName, BaseName))
      return true;
  }

  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL check for blob->data",
                       "API misuse")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
    if (!Condition)
      return;

    const LocationContext *LC = C.getLocationContext();
    if (!LC)
      return;

    const Decl *D = LC->getDecl();
    const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
    if (!FD || FD->getNameAsString() != "Curl_setblobopt")
      return;

    // The condition must validate the length field.
    if (!containsMemberAccess(Condition, "len", "blob"))
      return;

    // If it also validates the data pointer, the NULL check is present.
    if (containsMemberAccess(Condition, "data", "blob"))
      return;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Missing NULL check for blob->data in length validation", N);
    Report->addRange(Condition->getSourceRange());
    C.emitReport(std::move(Report));
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL check for blob->data when validating blob->len in "
      "Curl_setblobopt",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
