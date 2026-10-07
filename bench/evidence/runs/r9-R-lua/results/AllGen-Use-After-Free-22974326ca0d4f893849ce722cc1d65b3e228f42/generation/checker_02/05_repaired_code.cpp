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
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "knighter/roles.h"

#include <memory>
#include <vector>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "GC object used without root", "Use After Free")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  const ValueDecl *getValueDecl(const Expr *E) const;
  bool stmtHasRoleName(const Stmt *S, StringRef Role,
                       CheckerContext &C) const;
  bool containsDeclRef(const Stmt *S, const ValueDecl *VD) const;
  void reportMissingRoot(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

const ValueDecl *SAGenTestChecker::getValueDecl(const Expr *E) const {
  if (!E)
    return nullptr;
  E = E->IgnoreParenCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E))
    return DRE->getDecl();
  return nullptr;
}

bool SAGenTestChecker::stmtHasRoleName(const Stmt *S, StringRef Role,
                                       CheckerContext &C) const {
  if (!S)
    return false;
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(S->getSourceRange());
  StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
  for (const std::string &Name : knighter::roleNames(Role)) {
    if (Text.contains(StringRef(Name)))
      return true;
  }
  return false;
}

bool SAGenTestChecker::containsDeclRef(const Stmt *S,
                                       const ValueDecl *VD) const {
  if (!S || !VD)
    return false;
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (DRE->getDecl() == VD)
      return true;
  }
  for (const Stmt *Child : S->children()) {
    if (containsDeclRef(Child, VD))
      return true;
  }
  return false;
}

void SAGenTestChecker::reportMissingRoot(const CallEvent &Call,
                                         CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "GC object may be collected during gc_trigger: missing root before call",
      N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

static bool containsStmt(const Stmt *Parent, const Stmt *Child) {
  if (!Parent || !Child)
    return false;
  if (Parent == Child)
    return true;
  for (const Stmt *S : Parent->children()) {
    if (containsStmt(S, Child))
      return true;
  }
  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "gc_trigger"))
    return;

  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
  if (!CE || CE->getNumArgs() < 2)
    return;

  const Expr *TableArg = CE->getArg(1);
  const ValueDecl *TableDecl = getValueDecl(TableArg);
  if (!TableDecl)
    return;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(CE, C);
  if (!CS)
    return;

  // Locate the direct child of CS that contains the call.
  unsigned CallIdx = 0;
  bool Found = false;
  std::vector<const Stmt *> Body(CS->body().begin(), CS->body().end());
  for (unsigned i = 0; i < Body.size(); ++i) {
    if (containsStmt(Body[i], CE)) {
      CallIdx = i;
      Found = true;
      break;
    }
  }
  if (!Found)
    return;

  // Scan backwards for a ref_get on the same object.
  for (unsigned i = CallIdx; i > 0; --i) {
    const Stmt *Prev = Body[i - 1];
    if (stmtHasRoleName(Prev, "ref_get", C)) {
      if (containsDeclRef(Prev, TableDecl)) {
        return; // Found a root.
      }
    }
  }

  reportMissingRoot(Call, C);
}

//===----------------------------------------------------------------------===//
// Checker Registration
//===----------------------------------------------------------------------===//

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects GC objects used across a GC-triggering call without a root",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "gc_trigger": {
    "names": ["luaH_finishset"],
    "description": "call that may trigger an emergency garbage collection; its object argument must be kept alive by a root"
  },
  "ref_get": {
    "names": ["sethvalue2s"],
    "description": "stores a garbage-collected object into a root location (e.g., stack) to keep it alive during a GC-triggering call"
  }
}
*/
