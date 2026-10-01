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
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

static const TaintTagType LengthDelimitedTag = 0x1234;

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Unbounded string function on length-delimited buffer",
                       "Memory Safety")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  bool isLengthDelimited(SVal V, ProgramStateRef State) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "memchr", C))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();

  SymbolRef Sym = RetVal.getAsSymbol(true);
  if (!Sym) {
    if (const MemRegion *MR = RetVal.getAsRegion()) {
      MR = MR->getBaseRegion();
      if (const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(MR))
        Sym = SR->getSymbol();
    }
  }

  if (Sym) {
    State = addTaint(State, Sym, LengthDelimitedTag);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  bool isStrstr = ExprHasName(OriginExpr, "strstr", C);
  bool isStrchr = ExprHasName(OriginExpr, "strchr", C);
  if (!isStrstr && !isStrchr)
    return;

  if (Call.getNumArgs() < 1)
    return;

  SVal Haystack = Call.getArgSVal(0);
  ProgramStateRef State = C.getState();
  if (!isLengthDelimited(Haystack, State))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unbounded string function on length-delimited buffer", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

bool SAGenTestChecker::isLengthDelimited(SVal V, ProgramStateRef State) const {
  if (SymbolRef Sym = V.getAsSymbol()) {
    if (isTainted(State, Sym, LengthDelimitedTag))
      return true;
  }

  if (const MemRegion *MR = V.getAsRegion()) {
    MR = MR->getBaseRegion();
    if (const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(MR)) {
      SymbolRef Sym = SR->getSymbol();
      if (isTainted(State, Sym, LengthDelimitedTag))
        return true;
    }
  }

  return false;
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded string functions on length-delimited buffers",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
