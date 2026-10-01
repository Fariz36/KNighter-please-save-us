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
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(LengthDelimitedSymbols, SymbolRef)

namespace {

static bool getPrintfLikeFormatArg(StringRef Name, unsigned &FormatArg) {
  if (Name == "printf" || Name == "curl_mprintf") {
    FormatArg = 0;
    return true;
  }
  if (Name == "fprintf" || Name == "sprintf" ||
      Name == "curl_mfprintf" || Name == "curl_msprintf") {
    FormatArg = 1;
    return true;
  }
  if (Name == "snprintf" || Name == "curl_msnprintf") {
    FormatArg = 2;
    return true;
  }
  if (Name == "failf" || Name == "Curl_failf" ||
      Name == "infof" || Name == "Curl_infof" ||
      Name == "warnf" || Name == "Curl_warnf" ||
      Name == "debugf" || Name == "Curl_debugf") {
    FormatArg = 1;
    return true;
  }
  return false;
}

static void findUnboundedStringArgs(StringRef Fmt, unsigned FormatArg,
                                    llvm::SmallVectorImpl<unsigned> &ArgIndices) {
  unsigned ArgIdx = FormatArg + 1;
  for (size_t i = 0; i < Fmt.size(); ++i) {
    if (Fmt[i] != '%')
      continue;
    ++i;
    if (i >= Fmt.size())
      break;
    if (Fmt[i] == '%')
      continue;

    bool HasPrecision = false;

    // flags
    while (i < Fmt.size() && (Fmt[i] == '-' || Fmt[i] == '+' ||
                              Fmt[i] == ' ' || Fmt[i] == '#' ||
                              Fmt[i] == '0' || Fmt[i] == '\''))
      ++i;

    // width
    if (i < Fmt.size() && Fmt[i] == '*') {
      ++ArgIdx;
      ++i;
    } else {
      while (i < Fmt.size() && Fmt[i] >= '0' && Fmt[i] <= '9')
        ++i;
    }

    // precision
    if (i < Fmt.size() && Fmt[i] == '.') {
      HasPrecision = true;
      ++i;
      if (i < Fmt.size() && Fmt[i] == '*') {
        ++ArgIdx;
        ++i;
      } else {
        while (i < Fmt.size() && Fmt[i] >= '0' && Fmt[i] <= '9')
          ++i;
      }
    }

    // length modifiers
    while (i < Fmt.size() && (Fmt[i] == 'h' || Fmt[i] == 'l' ||
                              Fmt[i] == 'j' || Fmt[i] == 'z' ||
                              Fmt[i] == 't' || Fmt[i] == 'L' ||
                              Fmt[i] == 'q'))
      ++i;

    if (i >= Fmt.size())
      break;

    char Conv = Fmt[i];
    if (Conv == 's') {
      if (!HasPrecision)
        ArgIndices.push_back(ArgIdx);
      ++ArgIdx;
    } else if (Conv != '%' && Conv != 'm') {
      ++ArgIdx;
    }
  }
}

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Treating length-delimited ASN.1 data as NUL-terminated C string",
                       "API misuse")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const IdentifierInfo *ID = Call.getCalleeIdentifier();
  if (!ID || ID->getName() != "ASN1_STRING_get0_data")
    return;

  ProgramStateRef State = C.getState();
  SymbolRef Sym = Call.getReturnValue().getAsSymbol();
  if (!Sym)
    return;

  State = State->add<LengthDelimitedSymbols>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const IdentifierInfo *ID = Call.getCalleeIdentifier();
  if (!ID)
    return;

  StringRef Name = ID->getName();
  ProgramStateRef State = C.getState();

  // Case 1: strlen
  if (Name == "strlen" || Name == "__builtin_strlen") {
    if (Call.getNumArgs() < 1)
      return;
    SVal ArgVal = Call.getArgSVal(0);
    SymbolRef Sym = ArgVal.getAsSymbol();
    if (Sym && State->contains<LengthDelimitedSymbols>(Sym))
      reportBug(Call, C);
    return;
  }

  // Case 2: printf-like functions with unbounded %s
  unsigned FormatArg = 0;
  if (!getPrintfLikeFormatArg(Name, FormatArg))
    return;

  if (Call.getNumArgs() <= FormatArg)
    return;

  const CallExpr *CE = dyn_cast<CallExpr>(Call.getOriginExpr());
  if (!CE)
    return;

  const Expr *FmtE = CE->getArg(FormatArg);
  if (!FmtE)
    return;

  const StringLiteral *SL = dyn_cast<StringLiteral>(FmtE->IgnoreParenImpCasts());
  if (!SL)
    return;

  llvm::SmallVector<unsigned, 4> UnboundedArgs;
  findUnboundedStringArgs(SL->getString(), FormatArg, UnboundedArgs);

  for (unsigned ArgIdx : UnboundedArgs) {
    if (ArgIdx >= Call.getNumArgs())
      continue;
    SVal ArgVal = Call.getArgSVal(ArgIdx);
    SymbolRef Sym = ArgVal.getAsSymbol();
    if (Sym && State->contains<LengthDelimitedSymbols>(Sym)) {
      reportBug(Call, C);
      break;
    }
  }
}

void SAGenTestChecker::reportBug(const CallEvent &Call,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Treating length-delimited ASN.1 data as NUL-terminated C string", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects treating length-delimited ASN.1 data as NUL-terminated C string",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
