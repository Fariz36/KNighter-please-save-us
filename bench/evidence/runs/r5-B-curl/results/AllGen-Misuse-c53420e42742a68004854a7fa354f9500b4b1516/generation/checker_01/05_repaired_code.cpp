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
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "llvm/ADT/StringRef.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(LengthDelimitedPtrMap, SymbolRef, bool)

namespace {

static bool isFunctionNamed(const CallEvent &Call, StringRef Name,
                            CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, Name, C);
}

static bool isASN1StringGet0Data(const CallEvent &Call, CheckerContext &C) {
  return isFunctionNamed(Call, "ASN1_STRING_get0_data", C);
}

static SymbolRef getPointerSymbol(SVal V) {
  if (SymbolRef Sym = V.getAsSymbol())
    return Sym;

  if (const MemRegion *MR = V.getAsRegion()) {
    if (const SymbolicRegion *SR = dyn_cast<SymbolicRegion>(MR))
      return SR->getSymbol();
  }
  return nullptr;
}

static bool isLengthDelimited(ProgramStateRef State, const Expr *E,
                              CheckerContext &C) {
  if (!E)
    return false;

  SVal V = State->getSVal(E, C.getLocationContext());
  SymbolRef Sym = getPointerSymbol(V);
  if (!Sym)
    return false;

  return State->get<LengthDelimitedPtrMap>(Sym) != nullptr;
}

static bool isPrintfLike(StringRef Name) {
  return Name == "failf" || Name == "infof" || Name == "printf" ||
         Name == "fprintf" || Name == "sprintf" || Name == "snprintf";
}

static int getFormatArgIndex(StringRef Name) {
  if (Name == "failf" || Name == "infof" || Name == "fprintf")
    return 1;
  if (Name == "printf")
    return 0;
  if (Name == "sprintf")
    return 1;
  if (Name == "snprintf")
    return 2;
  return -1;
}

static StringRef getPrintfLikeName(const CallEvent &Call) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef Name = ID->getName();
    if (isPrintfLike(Name))
      return Name;
  }
  return StringRef();
}

static bool isFlagChar(char C) {
  return C == '-' || C == '+' || C == ' ' || C == '#' || C == '0';
}

static bool isDigitChar(char C) {
  return C >= '0' && C <= '9';
}

static bool isLengthModifier(char C) {
  return C == 'h' || C == 'l' || C == 'j' || C == 'z' || C == 't' || C == 'L';
}

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Length-delimited ASN1 data misuse",
                       "Security")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportMisuse(CheckerContext &C, const Expr *E, StringRef Msg) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isASN1StringGet0Data(Call, C))
    return;

  ProgramStateRef State = C.getState();
  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = getPointerSymbol(Ret);
  if (!Sym)
    return;

  State = State->set<LengthDelimitedPtrMap>(Sym, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isFunctionNamed(Call, "strlen", C)) {
    if (Call.getNumArgs() > 0) {
      const Expr *Arg = Call.getArgExpr(0);
      if (isLengthDelimited(State, Arg, C)) {
        reportMisuse(C, Arg,
                     "Length-delimited ASN1 data used as NUL-terminated string");
      }
    }
    return;
  }

  StringRef Name = getPrintfLikeName(Call);
  if (Name.empty())
    return;

  int FmtIdx = getFormatArgIndex(Name);
  if (FmtIdx < 0 || (unsigned)FmtIdx >= Call.getNumArgs())
    return;

  const Expr *FmtExpr = Call.getArgExpr(FmtIdx);
  const StringLiteral *SL =
      dyn_cast<StringLiteral>(FmtExpr->IgnoreParenImpCasts());
  if (!SL)
    return;

  StringRef Fmt = SL->getString();
  unsigned ArgIndex = FmtIdx + 1;

  for (unsigned i = 0; i < Fmt.size(); ++i) {
    if (Fmt[i] != '%')
      continue;

    ++i;
    if (i >= Fmt.size())
      break;

    if (Fmt[i] == '%')
      continue;

    unsigned StarCount = 0;
    bool HasPrecision = false;

    while (i < Fmt.size() && isFlagChar(Fmt[i]))
      ++i;

    if (i < Fmt.size() && Fmt[i] == '*') {
      ++StarCount;
      ++i;
    } else {
      while (i < Fmt.size() && isDigitChar(Fmt[i]))
        ++i;
    }

    if (i < Fmt.size() && Fmt[i] == '.') {
      HasPrecision = true;
      ++i;
      if (i < Fmt.size() && Fmt[i] == '*') {
        ++StarCount;
        ++i;
      } else {
        while (i < Fmt.size() && isDigitChar(Fmt[i]))
          ++i;
      }
    }

    while (i < Fmt.size() && isLengthModifier(Fmt[i]))
      ++i;

    if (i >= Fmt.size())
      break;

    char Conv = Fmt[i];
    ArgIndex += StarCount;

    if (Conv == 's' && !HasPrecision) {
      if (ArgIndex < Call.getNumArgs()) {
        const Expr *Arg = Call.getArgExpr(ArgIndex);
        if (isLengthDelimited(State, Arg, C)) {
          reportMisuse(C, Arg, "Length-delimited ASN1 data used with %s");
        }
      }
    }

    ++ArgIndex;
  }
}

void SAGenTestChecker::reportMisuse(CheckerContext &C, const Expr *E,
                                    StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (E)
    Report->addRange(E->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects treating length-delimited ASN1 data as NUL-terminated strings",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
