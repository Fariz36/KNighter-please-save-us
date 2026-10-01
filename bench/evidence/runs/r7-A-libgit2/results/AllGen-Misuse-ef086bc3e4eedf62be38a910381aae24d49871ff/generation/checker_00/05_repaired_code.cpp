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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Inverted memcmp comparison", "Logic Error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee)
    return;

  StringRef Name = Callee->getName();
  if (Name != "memcmp" && Name != "__builtin_memcmp")
    return;

  const Expr *CE = Call.getOriginExpr();
  if (!CE)
    return;

  // Find the first enclosing unary operator.  For !!memcmp(...), this should
  // be the inner logical-not operator.
  const UnaryOperator *InnerNot =
      findSpecificTypeInParents<UnaryOperator>(CE, C);
  if (!InnerNot || InnerNot->getOpcode() != UO_LNot)
    return;

  if (InnerNot->getSubExpr()->IgnoreParenImpCasts() != CE)
    return;

  // Find the next enclosing unary operator.  For !!memcmp(...), this should
  // be the outer logical-not operator.
  const UnaryOperator *OuterNot =
      findSpecificTypeInParents<UnaryOperator>(InnerNot, C);
  if (!OuterNot || OuterNot->getOpcode() != UO_LNot)
    return;

  if (OuterNot->getSubExpr()->IgnoreParenImpCasts() != InnerNot)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "!!memcmp() inverts comparison; use memcmp(...) == 0 instead",
      N);
  Report->addRange(OuterNot->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects inverted comparison from !!memcmp()",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
