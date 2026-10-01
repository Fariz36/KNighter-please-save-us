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
#include "clang/AST/Type.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Casting.h"

#include <memory>
#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map: marks memory regions returned by ASN1 length-delimited APIs.
REGISTER_MAP_WITH_PROGRAMSTATE(ASN1LenBufferMap, const MemRegion *, bool)

namespace {

//----------------------------------------------------------------------
// Helper functions
//----------------------------------------------------------------------

static bool isNamedFunction(const CallEvent &Call, StringRef Name) {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier())
    return ID->getName() == Name;
  return false;
}

static bool isASN1Get0Data(const CallEvent &Call) {
  return isNamedFunction(Call, "ASN1_STRING_get0_data");
}

static bool isASN1ToUTF8(const CallEvent &Call) {
  return isNamedFunction(Call, "ASN1_STRING_to_UTF8");
}

static bool isStrlen(const CallEvent &Call) {
  return isNamedFunction(Call, "strlen");
}

static bool isPrintfLike(const CallEvent &Call, unsigned &FmtIdx) {
  const IdentifierInfo *ID = Call.getCalleeIdentifier();
  if (!ID)
    return false;

  StringRef Name = ID->getName();
  if (Name == "printf" || Name == "vprintf") {
    FmtIdx = 0;
    return true;
  }
  if (Name == "fprintf" || Name == "vfprintf" ||
      Name == "sprintf" || Name == "vsprintf" ||
      Name == "failf" || Name == "infof" ||
      Name == "Curl_failf" || Name == "Curl_infof") {
    FmtIdx = 1;
    return true;
  }
  if (Name == "snprintf" || Name == "vsnprintf") {
    FmtIdx = 2;
    return true;
  }
  return false;
}

// Parses a printf format string and collects the variadic argument indices
// (relative to the first variadic argument) of any `%s` without precision.
static void parseFormatString(StringRef Fmt,
                              llvm::SmallVectorImpl<unsigned> &StrArgIndices) {
  unsigned ArgIdx = 0; // index into the variadic argument list
  for (size_t i = 0; i < Fmt.size(); ++i) {
    if (Fmt[i] != '%')
      continue;

    // Handle "%%"
    if (i + 1 < Fmt.size() && Fmt[i + 1] == '%') {
      ++i;
      continue;
    }

    size_t j = i + 1;

    // Flags
    while (j < Fmt.size() && (Fmt[j] == '-' || Fmt[j] == '+' ||
                              Fmt[j] == ' ' || Fmt[j] == '#' ||
                              Fmt[j] == '0'))
      ++j;

    // Width
    bool widthStar = false;
    if (j < Fmt.size() && Fmt[j] == '*') {
      widthStar = true;
      ++j;
    } else {
      while (j < Fmt.size() && Fmt[j] >= '0' && Fmt[j] <= '9')
        ++j;
    }

    // Precision
    bool hasPrecision = false;
    bool precStar = false;
    if (j < Fmt.size() && Fmt[j] == '.') {
      hasPrecision = true;
      ++j;
      if (j < Fmt.size() && Fmt[j] == '*') {
        precStar = true;
        ++j;
      } else {
        while (j < Fmt.size() && Fmt[j] >= '0' && Fmt[j] <= '9')
          ++j;
      }
    }

    // Length modifiers
    while (j < Fmt.size() && (Fmt[j] == 'h' || Fmt[j] == 'l' ||
                              Fmt[j] == 'j' || Fmt[j] == 'z' ||
                              Fmt[j] == 't' || Fmt[j] == 'L'))
      ++j;

    if (j >= Fmt.size())
      break;

    char conv = Fmt[j];

    // Account for '*' width and precision arguments.
    if (widthStar) ++ArgIdx;
    if (precStar) ++ArgIdx;

    if (conv == 's') {
      if (!hasPrecision) {
        StrArgIndices.push_back(ArgIdx);
      }
    }

    // The conversion itself consumes one argument.
    ++ArgIdx;
    i = j;
  }
}

//----------------------------------------------------------------------
// Checker class
//----------------------------------------------------------------------
class SAGenTestChecker : public Checker<eval::Call, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "ASN1 length-delimited buffer misuse",
                       "Security")) {}

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void report(CheckerContext &C, StringRef Msg, SourceRange Range) const;
};

//----------------------------------------------------------------------
// evalCall: model ASN1 length-delimited buffer APIs
//----------------------------------------------------------------------
bool SAGenTestChecker::evalCall(const CallEvent &Call,
                                CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return false;

  const CallExpr *CE = dyn_cast<CallExpr>(Origin);
  if (!CE)
    return false;

  SValBuilder &SVB = C.getSValBuilder();
  const LocationContext *LCtx = C.getLocationContext();
  unsigned Count = C.blockCount();

  // Model ASN1_STRING_get0_data: returns a pointer to the ASN1 buffer.
  if (isASN1Get0Data(Call)) {
    SVal RetVal = SVB.getConjuredHeapSymbolVal(CE, LCtx, Count);
    const MemRegion *BufferRegion = RetVal.getAsRegion();
    if (!BufferRegion)
      return false;

    State = State->BindExpr(CE, LCtx, RetVal);
    State = State->set<ASN1LenBufferMap>(BufferRegion, true);
    C.addTransition(State);
    return true;
  }

  // Model ASN1_STRING_to_UTF8: writes an allocated buffer into *out.
  if (isASN1ToUTF8(Call)) {
    // First argument is the address of the output pointer (e.g., &cn).
    SVal OutLocVal = Call.getArgSVal(0);
    std::optional<Loc> OutLoc = OutLocVal.getAs<Loc>();
    if (!OutLoc)
      return false;

    SVal BufferVal = SVB.getConjuredHeapSymbolVal(CE, LCtx, Count);
    const MemRegion *BufferRegion = BufferVal.getAsRegion();
    if (!BufferRegion)
      return false;

    // Bind the output pointer variable to the newly conjured buffer.
    State = State->bindLoc(*OutLoc, loc::MemRegionVal(BufferRegion), LCtx);

    // Bind the call return value to a conjured integer (the returned length).
    SVal RetVal = SVB.conjureSymbolVal(nullptr, CE, LCtx, Count);
    State = State->BindExpr(CE, LCtx, RetVal);

    State = State->set<ASN1LenBufferMap>(BufferRegion, true);
    C.addTransition(State);
    return true;
  }

  return false;
}

//----------------------------------------------------------------------
// checkPreCall: detect misuse of ASN1 length-delimited buffers
//----------------------------------------------------------------------
void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Detect strlen() on an ASN1 length-delimited buffer.
  if (isStrlen(Call)) {
    if (Call.getNumArgs() < 1)
      return;

    const Expr *Arg = Call.getArgExpr(0);
    if (!Arg)
      return;

    const MemRegion *MR = getMemRegionFromExpr(Arg, C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();

    if (State->get<ASN1LenBufferMap>(MR)) {
      report(C, "ASN1 length-delimited buffer used as NUL-terminated string (strlen)",
             Call.getSourceRange());
    }
    return;
  }

  // Detect printf-like use of %s without precision on an ASN1 buffer.
  unsigned FmtIdx = 0;
  if (isPrintfLike(Call, FmtIdx)) {
    if (FmtIdx >= Call.getNumArgs())
      return;

    const Expr *FmtExpr = Call.getArgExpr(FmtIdx);
    if (!FmtExpr)
      return;

    const StringLiteral *SL =
        dyn_cast<StringLiteral>(FmtExpr->IgnoreParenImpCasts());
    if (!SL)
      return;

    StringRef Fmt = SL->getString();
    llvm::SmallVector<unsigned, 4> StrArgIndices;
    parseFormatString(Fmt, StrArgIndices);

    for (unsigned ArgIdx : StrArgIndices) {
      unsigned ActualIdx = FmtIdx + 1 + ArgIdx;
      if (ActualIdx >= Call.getNumArgs())
        continue;

      const Expr *ArgExpr = Call.getArgExpr(ActualIdx);
      if (!ArgExpr)
        continue;

      const MemRegion *MR = getMemRegionFromExpr(ArgExpr, C);
      if (!MR)
        continue;
      MR = MR->getBaseRegion();

      if (State->get<ASN1LenBufferMap>(MR)) {
        report(C, "ASN1 length-delimited buffer passed to %s without precision",
               Call.getSourceRange());
      }
    }
  }
}

//----------------------------------------------------------------------
// report helper
//----------------------------------------------------------------------
void SAGenTestChecker::report(CheckerContext &C, StringRef Msg,
                              SourceRange Range) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  Report->addRange(Range);
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

//===----------------------------------------------------------------------===//
// Checker Registration
//===----------------------------------------------------------------------===//

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects misuse of ASN1 length-delimited buffers as NUL-terminated strings",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
