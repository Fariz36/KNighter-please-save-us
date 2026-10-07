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

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper: recursively check if an expression references a given role.
bool exprRefsRole(const Expr *E, StringRef Role) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
      if (knighter::declIsRole(FD, Role))
        return true;
    }
  } else if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const NamedDecl *D = DRE->getDecl()) {
      if (knighter::declIsRole(D, Role))
        return true;
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child)) {
      if (exprRefsRole(ChildE, Role))
        return true;
    }
  }
  return false;
}

// Helper: check if a condition is a proper bounds check for the cursor.
bool isBoundsCheckCondition(const Expr *Cond) {
  if (!Cond)
    return false;

  Cond = Cond->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return false;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_LT && Op != BO_LE)
    return false;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();

  return exprRefsRole(LHS, "cursor") &&
         exprRefsRole(LHS, "buffer_start") &&
         exprRefsRole(RHS, "buffer_length");
}

class SAGenTestChecker : public Checker<check::PreStmt<ArraySubscriptExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked lookahead read",
                       "Out-of-bounds read")) {}

  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE,
                                    CheckerContext &C) const {
  if (!ASE)
    return;

  // The base of the subscript must be the cursor field.
  const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
  const auto *ME = dyn_cast<MemberExpr>(Base);
  if (!ME)
    return;

  const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD || !knighter::declIsRole(FD, "cursor"))
    return;

  // Check whether this access originates from the lookahead macro.
  bool isLookahead = false;
  for (const auto &Name : knighter::roleNames("unchecked_lookahead_read")) {
    if (ExprHasName(ASE, Name, C)) {
      isLookahead = true;
      break;
    }
  }
  if (!isLookahead)
    return;

  // Find the closest enclosing conditional operator.
  const ConditionalOperator *CO =
      findSpecificTypeInParents<ConditionalOperator>(ASE, C);
  if (CO) {
    const Expr *TrueE = CO->getTrueExpr()->IgnoreParenImpCasts();
    if (TrueE == ASE && isBoundsCheckCondition(CO->getCond())) {
      // This lookahead read is bounds-checked; safe.
      return;
    }
  }

  // Report an unchecked lookahead read.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked lookahead read from string buffer", N);
  report->addRange(ASE->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked lookahead reads from string buffers",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "cursor": {"names": ["cur"], "description": "field holding the current read cursor into the input string"},
  "buffer_start": {"names": ["string"], "description": "field holding the start of the input string buffer"},
  "buffer_length": {"names": ["len"], "description": "field holding the length of the input string buffer"},
  "unchecked_lookahead_read": {"names": ["NXT"], "description": "macro/accessor that performs a lookahead read from the cursor without bounds checking"},
  "bounds_checked_lookahead_read": {"names": ["NXT"], "description": "macro/accessor that performs a bounds-checked lookahead read from the cursor"},
  "duplicator": {"names": ["xmlStrdup"], "description": "function that duplicates a C string into a newly allocated buffer"},
  "length_of": {"names": ["strlen"], "description": "standard C library function returning the length of a null-terminated string"},
  "null_check": {"names": [], "description": "explicit null check on the duplicated buffer pointer"}
}
*/
