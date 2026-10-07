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

REGISTER_MAP_WITH_PROGRAMSTATE(TokenTextMap, SymbolRef, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(TokenTypeMap, SymbolRef, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(BufferTokenMap, const MemRegion *, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(CheckedTokenTypes, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Dequote of unchecked token", "SQLite API")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void markTypeChecked(const Stmt *S, CheckerContext &C,
                       ProgramStateRef &State) const;
};

} // end anonymous namespace

static const Expr *getCallArgExpr(const CallEvent &Call, unsigned Idx) {
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return nullptr;
  const CallExpr *CE = dyn_cast<CallExpr>(Origin);
  if (!CE)
    return nullptr;
  if (Idx >= CE->getNumArgs())
    return nullptr;
  return CE->getArg(Idx);
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "parser_input"))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef LenSym = RetVal.getAsSymbol();
  if (!LenSym)
    return;

  const Expr *Arg0 = getCallArgExpr(Call, 0);
  const Expr *Arg1 = getCallArgExpr(Call, 1);
  if (!Arg0 || !Arg1)
    return;

  const MemRegion *TextReg = getMemRegionFromExpr(Arg0, C);
  if (!TextReg)
    return;
  TextReg = TextReg->getBaseRegion();

  const MemRegion *TypeReg = getMemRegionFromExpr(Arg1, C);
  if (!TypeReg)
    return;
  TypeReg = TypeReg->getBaseRegion();

  State = State->set<TokenTextMap>(LenSym, TextReg);
  State = State->set<TokenTypeMap>(LenSym, TypeReg);
  State = State->set<CheckedTokenTypes>(TypeReg, false);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (knighter::callIsRole(Call, "buffer_copy")) {
    const Expr *DestE = getCallArgExpr(Call, 0);
    const Expr *SrcE = getCallArgExpr(Call, 1);
    if (!DestE || !SrcE)
      return;

    SVal LenVal = Call.getArgSVal(2);
    SymbolRef LenSym = LenVal.getAsSymbol();
    if (!LenSym)
      return;

    const MemRegion *DestReg = getMemRegionFromExpr(DestE, C);
    if (!DestReg)
      return;
    DestReg = DestReg->getBaseRegion();

    const MemRegion *SrcReg = getMemRegionFromExpr(SrcE, C);
    if (!SrcReg)
      return;
    SrcReg = SrcReg->getBaseRegion();

    const MemRegion * const *MappedTextPtr =
        State->get<TokenTextMap>(LenSym);
    if (!MappedTextPtr)
      return;
    if (*MappedTextPtr != SrcReg)
      return;

    const MemRegion * const *TypeRegPtr =
        State->get<TokenTypeMap>(LenSym);
    if (!TypeRegPtr)
      return;
    const MemRegion *TypeReg = *TypeRegPtr;

    State = State->set<BufferTokenMap>(DestReg, TypeReg);
    C.addTransition(State);
    return;
  }

  if (knighter::callIsRole(Call, "dequoter")) {
    const Expr *Arg0 = getCallArgExpr(Call, 0);
    if (!Arg0)
      return;

    const MemRegion *ArgReg = getMemRegionFromExpr(Arg0, C);
    if (!ArgReg)
      return;
    ArgReg = ArgReg->getBaseRegion();

    const MemRegion * const *TypeRegPtr =
        State->get<BufferTokenMap>(ArgReg);
    if (!TypeRegPtr)
      return;
    const MemRegion *TypeReg = *TypeRegPtr;

    const bool *Checked = State->get<CheckedTokenTypes>(TypeReg);
    if (Checked && *Checked)
      return;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Dequote of unchecked token may assert on illegal token", N);
    report->addRange(Call.getSourceRange());
    C.emitReport(std::move(report));
  }
}

void SAGenTestChecker::markTypeChecked(const Stmt *S, CheckerContext &C,
                                       ProgramStateRef &State) const {
  if (!S)
    return;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      SVal Loc = State->getLValue(VD, C.getLocationContext());
      if (const MemRegion *MR = Loc.getAsRegion()) {
        MR = MR->getBaseRegion();
        const auto &Map = State->get<TokenTypeMap>();
        for (const auto &Entry : Map) {
          if (Entry.second == MR) {
            State = State->set<CheckedTokenTypes>(MR, true);
            break;
          }
        }
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    markTypeChecked(Child, C, State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;
  ProgramStateRef OldState = C.getState();
  ProgramStateRef State = OldState;
  markTypeChecked(Condition, C, State);
  if (State != OldState)
    C.addTransition(State);
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dequoting of tokens without checking for illegal token type",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {
    "names": ["getConstraintToken", "sqlite3GetToken"],
    "description": "returns a token length and writes a token type through an out-parameter; the token type distinguishes illegal/error tokens"
  },
  "buffer_copy": {
    "names": ["memcpy"],
    "description": "copies a number of bytes from a source pointer to a destination buffer"
  },
  "dequoter": {
    "names": ["sqlite3Dequote"],
    "description": "removes quoting/escaping from a token string; requires a valid quoted token and may assert on illegal input"
  },
  "aborting_assert": {
    "names": ["assert"],
    "description": "stops execution when its condition is false, so the dequoter's precondition must be satisfied"
  }
}
*/
