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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/StringRef.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool containsRoleField(const Stmt *S, llvm::StringRef Role,
                              CheckerContext &C) {
  if (!S)
    return false;

  (void)C;

  if (const Expr *E = dyn_cast<Expr>(S)) {
    E = E->IgnoreParenImpCasts();
    if (const auto *ME = dyn_cast<MemberExpr>(E)) {
      if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
        if (knighter::declIsRole(FD, Role))
          return true;
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (containsRoleField(Child, Role, C))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked indexed lookahead read",
                       "Bounds checking")) {}

  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;
  if (!S)
    return;

  const Expr *E = dyn_cast<Expr>(S);
  if (!E)
    return;

  E = E->IgnoreParenImpCasts();
  const auto *ASE = dyn_cast<ArraySubscriptExpr>(E);
  if (!ASE)
    return;

  const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
  const auto *ME = dyn_cast<MemberExpr>(Base);
  if (!ME)
    return;

  const auto *Field = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!Field)
    return;

  if (!knighter::declIsRole(Field, "cursor"))
    return;

  const auto *CO = findSpecificTypeInParents<ConditionalOperator>(ASE, C);
  if (CO && containsRoleField(CO->getCond(), "length_of", C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unchecked indexed lookahead read: cursor access lacks bounds check against length",
      N);
  Report->addRange(ASE->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked indexed lookahead reads on cursor without bounds check against length",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "cursor": {"names": ["cur"], "description": "pointer field in parser context that points into the input buffer and is advanced during parsing"},
  "length_of": {"names": ["len"], "description": "field storing the length of the input buffer for bounds checking"},
  "input_buffer": {"names": ["string"], "description": "NUL-terminated input string being parsed"},
  "lookahead_accessor": {"names": ["NXT"], "description": "macro that performs an indexed lookahead read from the cursor into the input buffer"}
}
*/
