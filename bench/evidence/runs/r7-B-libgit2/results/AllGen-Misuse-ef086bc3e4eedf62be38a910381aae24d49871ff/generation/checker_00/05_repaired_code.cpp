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
#include "clang/AST/Expr.h"
#include "clang/AST/OperationKinds.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Suspicious double-negated memcmp",
                       "Logic Error")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
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

  const UnaryOperator *Inner = findSpecificTypeInParents<UnaryOperator>(CE, C);
  if (!Inner || Inner->getOpcode() != UO_LNot)
    return;

  const UnaryOperator *Outer =
      findSpecificTypeInParents<UnaryOperator>(Inner, C);
  if (!Outer || Outer->getOpcode() != UO_LNot)
    return;

  const Expr *InnerExpr = Inner;
  if (Outer->getSubExpr()->IgnoreParenImpCasts() != InnerExpr)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Suspicious double-negated memcmp; use memcmp(...) == 0 for equality",
      N);
  report->addRange(Outer->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects suspicious !!memcmp(...) usage in equality checks",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
