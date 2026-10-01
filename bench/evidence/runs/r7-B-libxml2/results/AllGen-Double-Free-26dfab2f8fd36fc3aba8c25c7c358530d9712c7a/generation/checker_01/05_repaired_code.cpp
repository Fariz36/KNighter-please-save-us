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

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(ConsumedBufferMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double Free of XML Input Buffer",
                       "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  bool isCallTo(const CallEvent &Call, llvm::StringRef Name,
                CheckerContext &C) const;

  const MemRegion *getBaseArgRegion(const CallEvent &Call, unsigned Idx,
                                    CheckerContext &C) const;

  void reportDoubleFree(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isCallTo(const CallEvent &Call, llvm::StringRef Name,
                                CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, Name, C))
    return false;

  if (const IdentifierInfo *II = Call.getCalleeIdentifier())
    return II->getName() == Name;

  return false;
}

const MemRegion *SAGenTestChecker::getBaseArgRegion(const CallEvent &Call,
                                                    unsigned Idx,
                                                    CheckerContext &C) const {
  if (Idx >= Call.getNumArgs())
    return nullptr;

  const Expr *ArgExpr = Call.getArgExpr(Idx);
  if (!ArgExpr)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
  if (!MR)
    return nullptr;

  return MR->getBaseRegion();
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isCallTo(Call, "xmlNewIOInputStream", C))
    return;

  // xmlNewIOInputStream(ctxt, input, ...) consumes input.
  const MemRegion *MR = getBaseArgRegion(Call, 1, C);
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<ConsumedBufferMap>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isCallTo(Call, "xmlFreeParserInputBuffer", C))
    return;

  const MemRegion *MR = getBaseArgRegion(Call, 0, C);
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Consumed = State->get<ConsumedBufferMap>(MR);
  if (!Consumed || !*Consumed)
    return;

  reportDoubleFree(Call, C);
}

void SAGenTestChecker::reportDoubleFree(const CallEvent &Call,
                                        CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Double free: input buffer already consumed by xmlNewIOInputStream",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free of xmlParserInputBuffer consumed by "
      "xmlNewIOInputStream",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
