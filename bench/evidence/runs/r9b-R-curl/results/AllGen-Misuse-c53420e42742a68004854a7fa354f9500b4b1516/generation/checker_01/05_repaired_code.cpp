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

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(UntrustedSizeSymbols, SymbolRef)
REGISTER_SET_WITH_PROGRAMSTATE(LengthDelimitedRegions, const MemRegion *)

namespace {

static bool containsStmt(const Stmt *Root, const Stmt *Target) {
  if (!Root || !Target)
    return false;
  if (Root == Target)
    return true;
  for (const Stmt *Child : Root->children()) {
    if (containsStmt(Child, Target))
      return true;
  }
  return false;
}

static void collectRoleCalls(const Stmt *S, StringRef Role, ASTContext &Ctx,
                             SmallVectorImpl<const CallExpr *> &Out) {
  if (!S)
    return;
  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (knighter::callExprIsRole(CE, Role, Ctx))
      Out.push_back(CE);
  }
  for (const Stmt *Child : S->children())
    collectRoleCalls(Child, Role, Ctx, Out);
}

class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall, check::BranchCondition,
                     check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Length-delimited buffer treated as NUL-terminated string",
                       "String handling")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (knighter::callIsRole(Call, "untrusted_size")) {
    SVal RetVal = Call.getReturnValue();
    if (SymbolRef Sym = RetVal.getAsSymbol()) {
      ProgramStateRef State = C.getState();
      if (!State->contains<UntrustedSizeSymbols>(Sym)) {
        State = State->add<UntrustedSizeSymbols>(Sym);
        C.addTransition(State);
      }
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  ProgramStateRef State = C.getState();
  SmallVector<const CallExpr *, 4> LengthOfCalls;
  collectRoleCalls(Condition, "length_of", C.getASTContext(), LengthOfCalls);

  bool Changed = false;

  for (const CallExpr *CE : LengthOfCalls) {
    const BinaryOperator *BO = findSpecificTypeInParents<BinaryOperator>(CE, C);
    if (!BO)
      continue;

    const Expr *Other = nullptr;
    if (containsStmt(BO->getLHS(), CE))
      Other = BO->getRHS();
    else if (containsStmt(BO->getRHS(), CE))
      Other = BO->getLHS();

    if (!Other)
      continue;

    const Expr *OtherE = Other->IgnoreParenImpCasts();
    SVal OtherVal = State->getSVal(OtherE, C.getLocationContext());
    SymbolRef Sym = OtherVal.getAsSymbol();

    if (Sym && State->contains<UntrustedSizeSymbols>(Sym)) {
      // Report strlen on length-delimited buffer
      if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
        auto report = std::make_unique<PathSensitiveBugReport>(
            *BT, "strlen on length-delimited buffer; use bounded length instead",
            N);
        report->addRange(CE->getSourceRange());
        C.emitReport(std::move(report));
      }

      // Mark the buffer region as length-delimited
      if (CE->getNumArgs() > 0) {
        const Expr *Arg = CE->getArg(0);
        const MemRegion *MR = getMemRegionFromExpr(Arg, C);
        if (MR) {
          MR = MR->getBaseRegion();
          if (MR && !State->contains<LengthDelimitedRegions>(MR)) {
            State = State->add<LengthDelimitedRegions>(MR);
            Changed = true;
          }
        }
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "error_setter") &&
      !knighter::callIsRole(Call, "logger"))
    return;

  ProgramStateRef State = C.getState();

  int FormatIdx = -1;
  const StringLiteral *FormatSL = nullptr;

  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;
    const Expr *E = ArgE->IgnoreParenImpCasts();
    if (const StringLiteral *SL = dyn_cast<StringLiteral>(E)) {
      if (SL->getString().contains('%')) {
        FormatIdx = i;
        FormatSL = SL;
        break;
      }
    }
  }

  if (FormatIdx < 0 || !FormatSL)
    return;

  StringRef Format = FormatSL->getString();
  if (!Format.contains("%s"))
    return;

  for (unsigned i = FormatIdx + 1; i < Call.getNumArgs(); ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;

    const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
    if (!MR)
      continue;
    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    if (State->contains<LengthDelimitedRegions>(MR)) {
      if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
        auto report = std::make_unique<PathSensitiveBugReport>(
            *BT,
            "printf-style %s on length-delimited buffer; use %.*s with length",
            N);
        report->addRange(ArgE->getSourceRange());
        C.emitReport(std::move(report));
      }
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LocR = Loc.getAsRegion();
  if (!LocR)
    return;
  LocR = LocR->getBaseRegion();
  if (!LocR)
    return;

  const MemRegion *ValR = Val.getAsRegion();
  if (!ValR)
    return;
  ValR = ValR->getBaseRegion();
  if (!ValR)
    return;

  if (State->contains<LengthDelimitedRegions>(ValR) &&
      !State->contains<LengthDelimitedRegions>(LocR)) {
    State = State->add<LengthDelimitedRegions>(LocR);
    C.addTransition(State);
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects length-delimited buffers treated as NUL-terminated strings",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "length_of": {"names": ["strlen"], "description": "returns the length of a NUL-terminated string by scanning for a NUL byte"},
  "error_setter": {"names": ["failf"], "description": "printf-style function that records an error message; its format arguments must be valid C strings"},
  "logger": {"names": ["infof"], "description": "printf-style function that logs a message; its format arguments must be valid C strings"},
  "untrusted_size": {"names": ["ASN1_STRING_length"], "description": "returns the explicit length of a length-delimited buffer; the buffer is not guaranteed to be NUL-terminated"}
}
*/
