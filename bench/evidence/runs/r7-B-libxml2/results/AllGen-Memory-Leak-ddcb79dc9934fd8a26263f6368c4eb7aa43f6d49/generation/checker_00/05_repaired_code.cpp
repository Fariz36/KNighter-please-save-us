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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track symbols of pointers returned by owned allocation functions.
REGISTER_SET_WITH_PROGRAMSTATE(AllocatedPtrs, SymbolRef)

namespace {
class SAGenTestChecker : public Checker<check::PostCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory Leak", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Detect allocation functions by source name. This also handles calls
  // through function pointers such as libxml2's xmlMalloc.
  if (!ExprHasName(OriginExpr, "xmlMalloc", C) &&
      !ExprHasName(OriginExpr, "xmlRealloc", C))
    return;

  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = RetVal.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<AllocatedPtrs>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  const FieldRegion *FR = dyn_cast<FieldRegion>(MR);
  if (!FR)
    return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD || FD->getName() != "sax")
    return;

  const RecordDecl *RD = FD->getParent();
  if (!RD)
    return;

  StringRef RecordName = RD->getName();
  if (RecordName != "xmlParserCtxt" && RecordName != "_xmlParserCtxt")
    return;

  ProgramStateRef State = C.getState();
  SymbolRef ValSym = Val.getAsSymbol();
  if (!ValSym)
    return;

  if (!State->contains<AllocatedPtrs>(ValSym))
    return;

  SVal OldVal = State->getSVal(MR);
  if (OldVal.isZeroConstant())
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Memory leak: overwriting owned pointer field 'ctxt->sax' without "
      "freeing previous allocation.",
      N);
  if (StoreE)
    report->addRange(StoreE->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects overwriting owned pointer field without freeing previous allocation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
