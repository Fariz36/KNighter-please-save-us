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
#include "clang/AST/Decl.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/SmallVector.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(LengthDelimitedMap, const MemRegion *, bool)

namespace {

static bool isDataProvider(const CallEvent &Call) {
  return knighter::callIsRole(Call, "data_provider");
}

static bool isUnboundedConsumer(const CallEvent &Call) {
  return knighter::callIsRole(Call, "unbounded_string_consumer");
}

static ProgramStateRef markRegion(ProgramStateRef State, const MemRegion *R) {
  if (!R)
    return State;
  R = R->StripCasts();
  R = R->getBaseRegion();
  return State->set<LengthDelimitedMap>(R, true);
}

static bool isMarked(ProgramStateRef State, const MemRegion *R) {
  if (!R)
    return false;
  R = R->StripCasts();
  R = R->getBaseRegion();
  const bool *B = State->get<LengthDelimitedMap>(R);
  return B && *B;
}

static bool isDigit(char c) {
  return c >= '0' && c <= '9';
}

static bool isFormatFlag(char c) {
  return c == '-' || c == '+' || c == ' ' || c == '#' || c == '0';
}

static bool isLengthModifier(char c) {
  return c == 'h' || c == 'l' || c == 'j' || c == 'z' || c == 't' || c == 'L';
}

static llvm::SmallVector<unsigned, 4>
collectUnboundedStringArgIndices(const CallEvent &Call) {
  llvm::SmallVector<unsigned, 4> Indices;
  int FormatIdx = -1;
  const StringLiteral *SL = nullptr;

  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *Arg = Call.getArgExpr(i);
    if (!Arg)
      continue;
    Arg = Arg->IgnoreParenCasts();
    if (const auto *Lit = dyn_cast<StringLiteral>(Arg)) {
      SL = Lit;
      FormatIdx = i;
      break;
    }
  }

  if (!SL) {
    if (Call.getNumArgs() > 0)
      Indices.push_back(0);
    return Indices;
  }

  StringRef Fmt = SL->getString();
  unsigned ArgCursor = FormatIdx + 1;

  for (size_t i = 0; i < Fmt.size(); ++i) {
    if (Fmt[i] != '%')
      continue;
    ++i;
    if (i >= Fmt.size())
      break;
    if (Fmt[i] == '%')
      continue;

    while (i < Fmt.size() && isFormatFlag(Fmt[i]))
      ++i;

    if (i < Fmt.size() && Fmt[i] == '*') {
      ++ArgCursor;
      ++i;
    } else {
      while (i < Fmt.size() && isDigit(Fmt[i]))
        ++i;
    }

    bool precisionSpecified = false;
    if (i < Fmt.size() && Fmt[i] == '.') {
      precisionSpecified = true;
      ++i;
      if (i < Fmt.size() && Fmt[i] == '*') {
        ++ArgCursor;
        ++i;
      } else {
        while (i < Fmt.size() && isDigit(Fmt[i]))
          ++i;
      }
    }

    while (i < Fmt.size() && isLengthModifier(Fmt[i]))
      ++i;

    if (i >= Fmt.size())
      break;
    char conv = Fmt[i];

    if (conv == 's') {
      if (!precisionSpecified)
        Indices.push_back(ArgCursor);
      ++ArgCursor;
    } else {
      ++ArgCursor;
    }
  }

  return Indices;
}

class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Length-delimited buffer used as C string",
                       "Memory Safety")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                 CheckerContext &C) const;

private:
  void reportUse(const Expr *Arg, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isDataProvider(Call))
    return;

  ProgramStateRef State = C.getState();

  SVal Ret = Call.getReturnValue();
  if (const MemRegion *R = Ret.getAsRegion()) {
    State = markRegion(State, R);
  }

  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *Arg = Call.getArgExpr(i);
    if (!Arg)
      continue;

    const Expr *Cleaned = Arg->IgnoreParenImpCasts();
    const auto *UO = dyn_cast<UnaryOperator>(Cleaned);
    if (!UO || UO->getOpcode() != UO_AddrOf)
      continue;

    const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
    const auto *DRE = dyn_cast<DeclRefExpr>(Sub);
    if (!DRE)
      continue;

    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      continue;

    const MemRegion *StorageR = State->getRegion(VD, C.getLocationContext());
    if (StorageR)
      State = markRegion(State, StorageR);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isUnboundedConsumer(Call))
    return;

  ProgramStateRef State = C.getState();
  llvm::SmallVector<unsigned, 4> Indices =
      collectUnboundedStringArgIndices(Call);

  for (unsigned i : Indices) {
    if (i >= Call.getNumArgs())
      continue;

    const Expr *Arg = Call.getArgExpr(i);
    if (!Arg)
      continue;

    const Expr *Cleaned = Arg->IgnoreParenCasts();
    bool Marked = false;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(Cleaned)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        const MemRegion *StorageR =
            State->getRegion(VD, C.getLocationContext());
        if (isMarked(State, StorageR))
          Marked = true;
      }
    }

    if (!Marked) {
      SVal V = State->getSVal(Cleaned, C.getLocationContext());
      if (const MemRegion *MR = V.getAsRegion()) {
        if (isMarked(State, MR))
          Marked = true;
      }
    }

    if (Marked)
      reportUse(Arg, C);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  const MemRegion *DestR = Loc.getAsRegion();
  if (!DestR)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *SrcR = Val.getAsRegion();
  if (SrcR && isMarked(State, SrcR)) {
    State = markRegion(State, DestR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::reportUse(const Expr *Arg, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Length-delimited buffer used as NUL-terminated string", N);
  if (Arg)
    report->addRange(Arg->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of length-delimited buffers as NUL-terminated strings",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "data_provider": {
    "names": ["ASN1_STRING_get0_data", "ASN1_STRING_to_UTF8"],
    "description": "returns or writes back a pointer to a length-delimited byte buffer without guaranteeing a NUL terminator within the buffer length"
  },
  "length_provider": {
    "names": ["ASN1_STRING_length", "ASN1_STRING_to_UTF8"],
    "description": "returns the byte length associated with a length-delimited buffer"
  },
  "unbounded_string_consumer": {
    "names": ["strlen", "failf", "infof"],
    "description": "function or printf-style formatter that consumes a C string and requires NUL termination"
  },
  "bounded_nul_scanner": {
    "names": ["memchr"],
    "description": "scans a buffer within an explicit length for a NUL byte"
  },
  "bounded_string_formatter": {
    "names": [],
    "description": "printf-style formatting that bounds the consumed string by an explicit precision, e.g. %.*s"
  }
}
*/
