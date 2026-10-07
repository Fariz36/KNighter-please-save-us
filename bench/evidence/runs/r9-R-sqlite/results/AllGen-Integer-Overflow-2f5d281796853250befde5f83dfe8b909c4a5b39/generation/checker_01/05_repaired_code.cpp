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
#include "clang/Lex/Lexer.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Recursively check whether an expression contains a reference to a variable.
static bool containsVarDeclRef(const Stmt *S) {
  if (!S)
    return false;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (isa<VarDecl>(DRE->getDecl()))
      return true;
  }
  for (const Stmt *Child : S->children()) {
    if (containsVarDeclRef(Child))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow", "Assertion")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  bool isAbortingAssertCondition(const Stmt *Condition, CheckerContext &C) const;
  bool isNarrowExpr(const Expr *E, CheckerContext &C) const;
  bool isWideExpr(const Expr *E, CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isAbortingAssertCondition(const Stmt *Condition,
                                                 CheckerContext &C) const {
  SourceLocation Loc = Condition->getBeginLoc();
  if (!Loc.isMacroID())
    return false;
  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  StringRef MacroName = Lexer::getImmediateMacroName(Loc, SM, LangOpts);
  return knighter::isRole("aborting_assert", MacroName);
}

bool SAGenTestChecker::isNarrowExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;
  QualType Ty = E->getType();
  QualType CT = Ty.getCanonicalType();
  if (!CT->isIntegerType() || !CT->isSignedIntegerType())
    return false;
  unsigned Width = C.getASTContext().getTypeSize(CT);
  if (Width >= 64)
    return false;
  return containsVarDeclRef(E);
}

bool SAGenTestChecker::isWideExpr(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;
  QualType Ty = E->getType();
  QualType CT = Ty.getCanonicalType();
  if (!CT->isIntegerType() || !CT->isSignedIntegerType())
    return false;
  unsigned Width = C.getASTContext().getTypeSize(CT);
  if (Width < 64)
    return false;
  return containsVarDeclRef(E);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;
  if (!isAbortingAssertCondition(Condition, C))
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenImpCasts();

  // Optional leading logical not (e.g. assert(!(a > b))).
  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      CondE = UO->getSubExpr()->IgnoreParenImpCasts();
    }
  }

  const auto *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_LE && Op != BO_LT && Op != BO_GE && Op != BO_GT)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  bool LHSnarrow = isNarrowExpr(LHS, C);
  bool LHSwide = isWideExpr(LHS, C);
  bool RHSnarrow = isNarrowExpr(RHS, C);
  bool RHSwide = isWideExpr(RHS, C);

  if ((LHSnarrow && RHSwide) || (LHSwide && RHSnarrow)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "potential integer overflow in assertion: narrow arithmetic compared "
        "to 64-bit bound",
        N);
    report->addRange(Condition->getSourceRange());
    C.emitReport(std::move(report));
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potential integer overflow in assertions comparing narrow "
      "arithmetic to a 64-bit bound",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "aborting_assert": {"names": ["assert"], "description": "macro that aborts when its condition is false; the condition expression is evaluated for its truth value"},
  "length_of": {"names": ["sqlite3_value_bytes"], "description": "function that returns the length of a value"},
  "allocator": {"names": ["contextMalloc"], "description": "allocates memory"},
  "reallocator": {"names": ["sqlite3Realloc"], "description": "reallocates memory"},
  "deallocator": {"names": ["sqlite3_free"], "description": "frees memory"},
  "buffer_copy": {"names": ["memcpy"], "description": "copies bytes from one buffer to another"}
}
*/
