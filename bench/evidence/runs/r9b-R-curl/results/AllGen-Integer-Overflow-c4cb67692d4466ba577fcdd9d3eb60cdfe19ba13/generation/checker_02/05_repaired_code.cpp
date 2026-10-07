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
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/SmallVector.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps
REGISTER_MAP_WITH_PROGRAMSTATE(ParserInputSymbols, SymbolRef, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(NarrowParserInputs, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(CheckedNarrowParserInputs, const MemRegion *, bool)

namespace {

class SAGenTestChecker
  : public Checker<check::PostCall,
                   check::Bind,
                   check::BranchCondition,
                   check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow in Size Check", "Security")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C) const;
};

// Helper: collect all DeclRefExprs in a statement
static void collectDeclRefExprs(const Stmt *S,
                                llvm::SmallVectorImpl<const DeclRefExpr *> &Refs) {
  if (!S)
    return;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    Refs.push_back(DRE);
    return;
  }
  for (const Stmt *Child : S->children()) {
    collectDeclRefExprs(Child, Refs);
  }
}

// Helper: check if statement contains a sizeof expression
static bool containsSizeof(const Stmt *S) {
  if (!S)
    return false;
  if (const auto *UE = dyn_cast<UnaryExprOrTypeTraitExpr>(S)) {
    if (UE->getKind() == UETT_SizeOf)
      return true;
  }
  for (const Stmt *Child : S->children()) {
    if (containsSizeof(Child))
      return true;
  }
  return false;
}

// Track return values of parser_input functions
void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "parser_input"))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = RetVal.getAsSymbol();
  if (Sym) {
    State = State->set<ParserInputSymbols>(Sym, true);
    C.addTransition(State);
  }
}

// Mark narrow variables that are assigned from parser_input
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  SymbolRef Sym = Val.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  if (!State->get<ParserInputSymbols>(Sym))
    return;

  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;
  R = R->getBaseRegion();
  if (!R)
    return;

  const TypedValueRegion *TVR = dyn_cast<TypedValueRegion>(R);
  if (!TVR)
    return;
  QualType QT = TVR->getValueType();

  if (!QT->isIntegerType())
    return;

  ASTContext &ASTCtx = C.getASTContext();
  if (ASTCtx.getTypeSize(QT) >= ASTCtx.getTypeSize(ASTCtx.getSizeType()))
    return;

  State = State->set<NarrowParserInputs>(R, true);
  C.addTransition(State);
}

// Detect size checks involving narrow parser inputs
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!containsSizeof(Condition))
    return;

  llvm::SmallVector<const DeclRefExpr *, 8> Refs;
  collectDeclRefExprs(Condition, Refs);

  ProgramStateRef State = C.getState();
  bool Changed = false;
  for (const DeclRefExpr *DRE : Refs) {
    const MemRegion *MR = getMemRegionFromExpr(DRE, C);
    if (!MR)
      continue;
    MR = MR->getBaseRegion();
    if (State->get<NarrowParserInputs>(MR)) {
      State = State->set<CheckedNarrowParserInputs>(MR, true);
      Changed = true;
    }
  }
  if (Changed)
    C.addTransition(State);
}

// Detect buffer_copy using checked narrow parser inputs
void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "buffer_copy"))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;

    llvm::SmallVector<const DeclRefExpr *, 8> Refs;
    collectDeclRefExprs(ArgE, Refs);
    for (const DeclRefExpr *DRE : Refs) {
      const MemRegion *MR = getMemRegionFromExpr(DRE, C);
      if (!MR)
        continue;
      MR = MR->getBaseRegion();
      if (State->get<CheckedNarrowParserInputs>(MR)) {
        reportBug(Call, C);
        return;
      }
    }
  }
}

void SAGenTestChecker::reportBug(const CallEvent &Call,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Integer overflow in size check before buffer copy", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in size check before buffer copy",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["Curl_read16_le"], "description": "reads an integer field from untrusted parser input"},
  "buffer_copy": {"names": ["Curl_client_write"], "description": "copies data from a buffer to an output/sink"},
  "error_setter": {"names": ["failf"], "description": "printf-style function that records an error message; its format arguments must be valid C strings"}
}
*/
