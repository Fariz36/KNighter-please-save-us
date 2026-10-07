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

// Maps a token-text buffer region to the symbol of the token-type/status
// produced by the same parser_input call.
REGISTER_MAP_WITH_PROGRAMSTATE(TokenTextToTypeSymMap, const MemRegion *, SymbolRef)

// Tracks whether a token-type symbol has been checked before dequoting.
REGISTER_MAP_WITH_PROGRAMSTATE(TokenTypeCheckedMap, SymbolRef, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Dequoting Unchecked Parser Token",
                       "Parsing Error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  bool isTokenTypeOutParam(const Expr *ArgE, CheckerContext &C) const;
  bool markCheckedInExpr(const Expr *E, CheckerContext &C,
                         ProgramStateRef &State) const;
  void reportUncheckedDequote(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isTokenTypeOutParam(const Expr *ArgE,
                                           CheckerContext &C) const {
  if (!ArgE)
    return false;

  QualType Ty = ArgE->getType();
  if (!Ty->isPointerType())
    return false;

  QualType Pointee = Ty->getPointeeType();
  if (Pointee.isConstQualified())
    return false;

  return Pointee->isIntegerType() || Pointee->isEnumeralType();
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "parser_input"))
    return;

  ProgramStateRef State = C.getState();

  const Expr *TypeArgE = nullptr;
  unsigned TypeArgIdx = 0;
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    if (isTokenTypeOutParam(ArgE, C)) {
      TypeArgE = ArgE;
      TypeArgIdx = i;
      break;
    }
  }
  if (!TypeArgE)
    return;

  const Expr *TextArgE = nullptr;
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    if (i == TypeArgIdx)
      continue;
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;
    if (ArgE->getType()->isPointerType()) {
      TextArgE = ArgE;
      break;
    }
  }
  if (!TextArgE)
    return;

  const MemRegion *TextRegion = getMemRegionFromExpr(TextArgE, C);
  if (!TextRegion)
    return;
  TextRegion = TextRegion->getBaseRegion();
  if (!TextRegion)
    return;

  const MemRegion *TypeRegion = getMemRegionFromExpr(TypeArgE, C);
  if (!TypeRegion)
    return;
  // Do NOT call getBaseRegion() on TypeRegion: we need the exact scalar
  // out-parameter region to read its post-call value.

  SVal TypeVal = State->getSVal(TypeRegion);
  SymbolRef TypeSym = TypeVal.getAsSymbol();
  if (!TypeSym)
    return;

  State = State->set<TokenTextToTypeSymMap>(TextRegion, TypeSym);
  State = State->set<TokenTypeCheckedMap>(TypeSym, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (knighter::callIsRole(Call, "buffer_copy")) {
    if (Call.getNumArgs() < 2)
      return;

    const Expr *DestE = Call.getArgExpr(0);
    const Expr *SrcE = Call.getArgExpr(1);
    if (!DestE || !SrcE)
      return;

    const MemRegion *DestRegion = getMemRegionFromExpr(DestE, C);
    if (!DestRegion)
      return;
    DestRegion = DestRegion->getBaseRegion();
    if (!DestRegion)
      return;

    const MemRegion *SrcRegion = getMemRegionFromExpr(SrcE, C);
    if (!SrcRegion)
      return;
    SrcRegion = SrcRegion->getBaseRegion();
    if (!SrcRegion)
      return;

    if (const SymbolRef *TypeSym =
            State->get<TokenTextToTypeSymMap>(SrcRegion)) {
      State = State->set<TokenTextToTypeSymMap>(DestRegion, *TypeSym);
      C.addTransition(State);
    }
    return;
  }

  if (knighter::callIsRole(Call, "dequoter")) {
    if (Call.getNumArgs() < 1)
      return;

    const Expr *ArgE = Call.getArgExpr(0);
    if (!ArgE)
      return;

    const MemRegion *ArgRegion = getMemRegionFromExpr(ArgE, C);
    if (!ArgRegion)
      return;
    ArgRegion = ArgRegion->getBaseRegion();
    if (!ArgRegion)
      return;

    const SymbolRef *TypeSym = State->get<TokenTextToTypeSymMap>(ArgRegion);
    if (!TypeSym)
      return;

    const bool *Checked = State->get<TokenTypeCheckedMap>(*TypeSym);
    if (Checked && *Checked)
      return; // already checked

    reportUncheckedDequote(Call, C);
    return;
  }
}

void SAGenTestChecker::reportUncheckedDequote(const CallEvent &Call,
                                              CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Dequoting unchecked parser token", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

bool SAGenTestChecker::markCheckedInExpr(const Expr *E, CheckerContext &C,
                                         ProgramStateRef &State) const {
  if (!E)
    return false;

  bool Changed = false;

  SVal V = State->getSVal(E, C.getLocationContext());
  if (SymbolRef Sym = V.getAsSymbol()) {
    const bool *Checked = State->get<TokenTypeCheckedMap>(Sym);
    if (Checked && *Checked == false) {
      State = State->set<TokenTypeCheckedMap>(Sym, true);
      Changed = true;
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child)) {
      if (markCheckedInExpr(ChildE, C, State))
        Changed = true;
    }
  }

  return Changed;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();
  if (markCheckedInExpr(CondE, C, State)) {
    C.addTransition(State);
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dequoting of parser tokens without checking the token type",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["getConstraintToken", "sqlite3GetToken"], "description": "scans input buffer and returns token length; writes token type/status to an integer out-parameter; may report an illegal/malformed token"},
  "dequoter": {"names": ["sqlite3Dequote"], "description": "removes quoting from a string in place; expects a syntactically valid quoted token"},
  "buffer_copy": {"names": ["memcpy"], "description": "copies a bounded number of bytes from a source buffer to a destination buffer"}
}
*/
