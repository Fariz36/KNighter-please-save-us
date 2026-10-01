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

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track symbols returned by ASN1_STRING_get0_data().
// The boolean is true when the symbol points to length-delimited ASN1 data
// that may not be NUL-terminated.
REGISTER_MAP_WITH_PROGRAMSTATE(Asn1DataMap, SymbolRef, bool)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "ASN1_STRING as C string", "Memory safety")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void checkStrlen(const CallEvent &Call, CheckerContext &C) const;
  void checkFormattedOutput(const CallEvent &Call, CheckerContext &C) const;
  void reportBug(CheckerContext &C, const CallEvent &Call, StringRef Msg) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "ASN1_STRING_get0_data", C))
    return;

  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = RetVal.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<Asn1DataMap>(Sym, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  checkStrlen(Call, C);
  checkFormattedOutput(Call, C);
}

void SAGenTestChecker::checkStrlen(const CallEvent &Call,
                                   CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "strlen", C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  SVal Arg = Call.getArgSVal(0);
  SymbolRef Sym = Arg.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  if (State->get<Asn1DataMap>(Sym)) {
    reportBug(C, Call, "strlen() on non-NUL-terminated ASN1_STRING data");
  }
}

static bool isFormattedOutputCall(const CallEvent &Call, CheckerContext &C) {
  const IdentifierInfo *ID = Call.getCalleeIdentifier();
  if (ID) {
    StringRef Name = ID->getName();
    if (Name == "printf" || Name == "fprintf" || Name == "sprintf" ||
        Name == "snprintf" || Name == "vprintf" || Name == "vfprintf" ||
        Name == "vsprintf" || Name == "vsnprintf" || Name == "failf" ||
        Name == "infof" || Name == "Curl_failf" || Name == "Curl_infof" ||
        Name == "curl_mprintf" || Name == "curl_mfprintf" ||
        Name == "curl_msprintf" || Name == "curl_msnprintf")
      return true;
  }

  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;

  return ExprHasName(OriginExpr, "printf", C) ||
         ExprHasName(OriginExpr, "fprintf", C) ||
         ExprHasName(OriginExpr, "sprintf", C) ||
         ExprHasName(OriginExpr, "snprintf", C) ||
         ExprHasName(OriginExpr, "failf", C) ||
         ExprHasName(OriginExpr, "infof", C) ||
         ExprHasName(OriginExpr, "Curl_failf", C) ||
         ExprHasName(OriginExpr, "Curl_infof", C);
}

void SAGenTestChecker::checkFormattedOutput(const CallEvent &Call,
                                            CheckerContext &C) const {
  if (!isFormattedOutputCall(Call, C))
    return;

  // Find the first string literal among the call arguments.  For all
  // supported printf-like functions this is the format string.
  unsigned FormatIdx = 0;
  const StringLiteral *SL = nullptr;
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;
    ArgE = ArgE->IgnoreParenImpCasts();
    if (const StringLiteral *Lit = dyn_cast<StringLiteral>(ArgE)) {
      SL = Lit;
      FormatIdx = i;
      break;
    }
  }
  if (!SL)
    return;

  StringRef Fmt = SL->getString();
  unsigned ArgIdx = FormatIdx + 1;
  ProgramStateRef State = C.getState();

  for (size_t pos = 0; pos < Fmt.size(); ++pos) {
    if (Fmt[pos] != '%')
      continue;
    if (pos + 1 < Fmt.size() && Fmt[pos + 1] == '%') {
      ++pos;
      continue;
    }

    size_t i = pos + 1;
    bool widthStar = false;
    bool precisionStar = false;

    // flags
    while (i < Fmt.size() &&
           (Fmt[i] == '-' || Fmt[i] == '+' || Fmt[i] == ' ' ||
            Fmt[i] == '#' || Fmt[i] == '0' || Fmt[i] == '\'')) {
      ++i;
    }

    // width
    if (i < Fmt.size() && Fmt[i] == '*') {
      widthStar = true;
      ++i;
    } else {
      while (i < Fmt.size() && Fmt[i] >= '0' && Fmt[i] <= '9') {
        ++i;
      }
    }

    // precision
    if (i < Fmt.size() && Fmt[i] == '.') {
      ++i;
      if (i < Fmt.size() && Fmt[i] == '*') {
        precisionStar = true;
        ++i;
      } else {
        while (i < Fmt.size() && Fmt[i] >= '0' && Fmt[i] <= '9') {
          ++i;
        }
      }
    }

    // length modifiers
    while (i < Fmt.size() &&
           (Fmt[i] == 'h' || Fmt[i] == 'l' || Fmt[i] == 'L' ||
            Fmt[i] == 'j' || Fmt[i] == 'z' || Fmt[i] == 't')) {
      ++i;
    }

    if (i >= Fmt.size())
      break;

    char conv = Fmt[i];
    pos = i; // continue after the conversion character

    unsigned consumed = (widthStar ? 1 : 0) + (precisionStar ? 1 : 0);
    unsigned mainArgIdx = ArgIdx + consumed;

    // A plain %s assumes NUL termination.  %.*s is safe because it uses an
    // explicit precision argument as the length.
    if (conv == 's' && !precisionStar) {
      if (mainArgIdx < Call.getNumArgs()) {
        SVal ArgVal = Call.getArgSVal(mainArgIdx);
        SymbolRef Sym = ArgVal.getAsSymbol();
        if (Sym && State->get<Asn1DataMap>(Sym)) {
          reportBug(C, Call, "%s on non-NUL-terminated ASN1_STRING data");
        }
      }
    }

    // All standard conversions consume one main argument.
    ArgIdx += consumed + 1;
  }
}

void SAGenTestChecker::reportBug(CheckerContext &C, const CallEvent &Call,
                                 StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects treating length-delimited ASN1_STRING buffers as NUL-terminated "
      "C strings",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
