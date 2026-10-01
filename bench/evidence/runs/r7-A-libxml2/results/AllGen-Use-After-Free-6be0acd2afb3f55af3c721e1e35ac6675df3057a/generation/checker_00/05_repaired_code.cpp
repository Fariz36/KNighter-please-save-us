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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/Basic/IdentifierTable.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(UnlinkedNodes, const MemRegion *)

namespace {
class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing xmlUnlinkNodeInternal before xmlFreeNode",
                       "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  static bool isCalleeName(const CallEvent &Call, StringRef Name,
                           CheckerContext &C);
  void handleUnlink(const CallEvent &Call, CheckerContext &C) const;
  void handleFree(const CallEvent &Call, CheckerContext &C) const;
  void reportMissingUnlink(const CallEvent &Call, CheckerContext &C) const;
};
} // namespace

bool SAGenTestChecker::isCalleeName(const CallEvent &Call, StringRef Name,
                                    CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (E && ExprHasName(E, Name, C))
    return true;

  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == Name;

  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (isCalleeName(Call, "xmlUnlinkNodeInternal", C)) {
    handleUnlink(Call, C);
    return;
  }

  if (isCalleeName(Call, "xmlFreeNode", C)) {
    handleFree(Call, C);
    return;
  }
}

void SAGenTestChecker::handleUnlink(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (Call.getNumArgs() < 1)
    return;

  const MemRegion *MR = Call.getArgSVal(0).getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<UnlinkedNodes>(MR);
  C.addTransition(State);
}

void SAGenTestChecker::handleFree(const CallEvent &Call,
                                  CheckerContext &C) const {
  if (Call.getNumArgs() < 1)
    return;

  const Decl *D = C.getLocationContext()->getDecl();
  if (!D)
    return;

  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->getName().equals("xmlAddChild"))
    return;

  const MemRegion *MR = Call.getArgSVal(0).getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  if (!State->contains<UnlinkedNodes>(MR)) {
    reportMissingUnlink(Call, C);
  }
}

void SAGenTestChecker::reportMissingUnlink(const CallEvent &Call,
                                           CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "xmlFreeNode called without xmlUnlinkNodeInternal on possibly linked node.",
      N);

  const Expr *E = Call.getOriginExpr();
  if (E)
    report->addRange(E->getSourceRange());

  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects xmlFreeNode calls that may free a still-linked node without "
      "calling xmlUnlinkNodeInternal first",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
