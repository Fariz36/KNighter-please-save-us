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
#include "llvm/Support/Casting.h"
#include "llvm/ADT/StringRef.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

static const TaintTagType Asn1TaintTag = 101;

namespace {
class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "ASN1 String Misuse", "C String API Misuse")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C, StringRef Msg) const;
  static bool isCallTo(const CallEvent &Call, StringRef Name, CheckerContext &C);
  static ProgramStateRef addTaintToSVal(ProgramStateRef State, SVal Val,
                                        CheckerContext &C);
};
} // end anonymous namespace

bool SAGenTestChecker::isCallTo(const CallEvent &Call, StringRef Name,
                                CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;
  return ExprHasName(E, Name, C);
}

ProgramStateRef SAGenTestChecker::addTaintToSVal(ProgramStateRef State, SVal Val,
                                                 CheckerContext &C) {
  if (SymbolRef Sym = Val.getAsSymbol())
    State = taint::addTaint(State, Sym, Asn1TaintTag);
  else if (const MemRegion *MR = Val.getAsRegion())
    State = taint::addTaint(State, MR, Asn1TaintTag);
  return State;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isCallTo(Call, "ASN1_STRING_get0_data", C)) {
    SVal RetVal = Call.getReturnValue();
    State = addTaintToSVal(State, RetVal, C);
    C.addTransition(State);
  } else if (isCallTo(Call, "ASN1_STRING_to_UTF8", C)) {
    if (Call.getNumArgs() < 1)
      return;
    const Expr *Arg0 = Call.getArgExpr(0);
    if (!Arg0)
      return;
    const MemRegion *OutVarReg = getMemRegionFromExpr(Arg0, C);
    if (!OutVarReg)
      return;
    OutVarReg = OutVarReg->getBaseRegion();
    if (!OutVarReg)
      return;

    SVal OutVal = State->getSVal(OutVarReg);
    if (!OutVal.isUnknown()) {
      State = addTaintToSVal(State, OutVal, C);
    } else {
      State = taint::addTaint(State, OutVarReg, Asn1TaintTag);
    }
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isCallTo(Call, "strlen", C)) {
    if (Call.getNumArgs() < 1)
      return;
    SVal ArgVal = Call.getArgSVal(0);
    if (taint::isTainted(State, ArgVal, Asn1TaintTag)) {
      reportBug(Call, C,
                "strlen called on ASN.1 string that may not be NUL-terminated");
    }
    return;
  }

  int FmtIdx = -1;
  unsigned VarargStart = 0;
  if (isCallTo(Call, "failf", C) || isCallTo(Call, "Curl_failf", C) ||
      isCallTo(Call, "infof", C) || isCallTo(Call, "Curl_infof", C)) {
    FmtIdx = 1;
    VarargStart = 2;
  } else if (isCallTo(Call, "printf", C)) {
    FmtIdx = 0;
    VarargStart = 1;
  } else if (isCallTo(Call, "fprintf", C) || isCallTo(Call, "sprintf", C)) {
    FmtIdx = 1;
    VarargStart = 2;
  } else if (isCallTo(Call, "snprintf", C)) {
    FmtIdx = 2;
    VarargStart = 3;
  } else {
    return;
  }

  if (Call.getNumArgs() <= (unsigned)FmtIdx)
    return;
  const Expr *FmtExpr = Call.getArgExpr(FmtIdx);
  if (!FmtExpr)
    return;
  FmtExpr = FmtExpr->IgnoreImpCasts();
  const StringLiteral *SL = dyn_cast<StringLiteral>(FmtExpr);
  if (!SL)
    return;

  StringRef Fmt = SL->getString();
  unsigned ArgIdx = VarargStart;

  for (size_t i = 0; i < Fmt.size(); ++i) {
    if (Fmt[i] != '%')
      continue;
    if (i + 1 >= Fmt.size())
      break;
    if (Fmt[i + 1] == '%') {
      ++i;
      continue;
    }

    size_t j = i + 1;
    // flags
    while (j < Fmt.size() && (Fmt[j] == '-' || Fmt[j] == '+' ||
                              Fmt[j] == ' ' || Fmt[j] == '#' ||
                              Fmt[j] == '0'))
      ++j;
    // width
    bool widthStar = false;
    if (j < Fmt.size() && Fmt[j] == '*') {
      widthStar = true;
      ++j;
    } else {
      while (j < Fmt.size() && Fmt[j] >= '0' && Fmt[j] <= '9')
        ++j;
    }
    // precision
    bool precStar = false;
    if (j < Fmt.size() && Fmt[j] == '.') {
      ++j;
      if (j < Fmt.size() && Fmt[j] == '*') {
        precStar = true;
        ++j;
      } else {
        while (j < Fmt.size() && Fmt[j] >= '0' && Fmt[j] <= '9')
          ++j;
      }
    }
    // length modifiers
    while (j < Fmt.size() && (Fmt[j] == 'h' || Fmt[j] == 'l' ||
                              Fmt[j] == 'j' || Fmt[j] == 'z' ||
                              Fmt[j] == 't' || Fmt[j] == 'L'))
      ++j;
    if (j >= Fmt.size())
      break;
    char conv = Fmt[j];

    if (widthStar)
      ++ArgIdx;
    if (precStar)
      ++ArgIdx;

    if (conv == 's') {
      if (!precStar) {
        if (ArgIdx < Call.getNumArgs()) {
          SVal ArgVal = Call.getArgSVal(ArgIdx);
          if (taint::isTainted(State, ArgVal, Asn1TaintTag)) {
            reportBug(Call, C,
                      "ASN.1 string used with %s may not be NUL-terminated");
          }
        }
      }
      ++ArgIdx;
    } else {
      ++ArgIdx;
    }
    i = j;
  }
}

void SAGenTestChecker::reportBug(const CallEvent &Call, CheckerContext &C,
                                 StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects ASN.1 length-delimited strings used as NUL-terminated C strings",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
