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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static constexpr TaintTagType UntrustedLenBufTag = 0x1001;

static ProgramStateRef addTaintToSVal(ProgramStateRef State, SVal V,
                                      TaintTagType Tag) {
  if (SymbolRef Sym = V.getAsSymbol())
    return addTaint(State, Sym, Tag);
  if (const MemRegion *MR = V.getAsRegion())
    return addTaint(State, MR, Tag);
  return State;
}

static bool isSValTainted(ProgramStateRef State, SVal V, TaintTagType Tag) {
  if (SymbolRef Sym = V.getAsSymbol())
    if (isTainted(State, Sym, Tag))
      return true;
  if (const MemRegion *MR = V.getAsRegion())
    if (isTainted(State, MR, Tag))
      return true;
  return false;
}

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Untrusted length-delimited buffer used as C string",
                       "Security")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(CheckerContext &C, const Stmt *S, StringRef Msg) const;
};

} // end anonymous namespace

void SAGenTestChecker::reportBug(CheckerContext &C, const Stmt *S,
                                 StringRef Msg) const {
  if (!BT)
    return;
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (knighter::callIsRole(Call, "untrusted_data_accessor")) {
    SVal Ret = Call.getReturnValue();
    ProgramStateRef NewState = addTaintToSVal(State, Ret, UntrustedLenBufTag);
    C.addTransition(NewState);
    return;
  }

  if (knighter::callIsRole(Call, "allocator") &&
      knighter::callIsRole(Call, "untrusted_size")) {
    const Expr *OutExpr = nullptr;
    for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
      const Expr *Arg = Call.getArgExpr(i);
      if (!Arg)
        continue;
      const Expr *ArgNoCasts = Arg->IgnoreParenImpCasts();
      if (const auto *UO = dyn_cast<UnaryOperator>(ArgNoCasts)) {
        if (UO->getOpcode() == UO_AddrOf) {
          OutExpr = UO->getSubExpr()->IgnoreParenImpCasts();
          break;
        }
      }
    }
    if (!OutExpr)
      return;

    SVal OutVal = State->getSVal(OutExpr, C.getLocationContext());
    ProgramStateRef NewState = addTaintToSVal(State, OutVal, UntrustedLenBufTag);
    C.addTransition(NewState);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (knighter::callIsRole(Call, "length_of")) {
    if (Call.getNumArgs() > 0) {
      SVal Arg0 = Call.getArgSVal(0);
      if (isSValTainted(State, Arg0, UntrustedLenBufTag)) {
        reportBug(C, Call.getOriginExpr(),
                  "Length-delimited buffer passed to strlen; may read past end");
      }
    }
    return;
  }

  if (knighter::callIsRole(Call, "error_setter")) {
    for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
      const Expr *Arg = Call.getArgExpr(i);
      if (!Arg)
        continue;
      const Expr *ArgNoCasts = Arg->IgnoreParenImpCasts();
      const auto *SL = dyn_cast<StringLiteral>(ArgNoCasts);
      if (!SL)
        continue;

      StringRef Fmt = SL->getString();
      unsigned NextArg = i + 1;

      for (size_t j = 0; j < Fmt.size(); ++j) {
        if (Fmt[j] != '%')
          continue;
        if (j + 1 < Fmt.size() && Fmt[j + 1] == '%') {
          ++j;
          continue;
        }

        ++j; // skip '%'
        // flags
        while (j < Fmt.size() &&
               (Fmt[j] == '-' || Fmt[j] == '+' || Fmt[j] == ' ' ||
                Fmt[j] == '#' || Fmt[j] == '0'))
          ++j;

        unsigned WidthStars = 0;
        while (j < Fmt.size() && Fmt[j] == '*') {
          ++WidthStars;
          ++j;
        }
        while (j < Fmt.size() && Fmt[j] >= '0' && Fmt[j] <= '9')
          ++j;

        bool HasPrecision = false;
        bool PrecisionStar = false;
        if (j < Fmt.size() && Fmt[j] == '.') {
          HasPrecision = true;
          ++j;
          if (j < Fmt.size() && Fmt[j] == '*') {
            PrecisionStar = true;
            ++j;
          }
          while (j < Fmt.size() && Fmt[j] >= '0' && Fmt[j] <= '9')
            ++j;
        }

        while (j < Fmt.size() &&
               (Fmt[j] == 'h' || Fmt[j] == 'l' || Fmt[j] == 'L' ||
                Fmt[j] == 'j' || Fmt[j] == 'z' || Fmt[j] == 't'))
          ++j;

        if (j >= Fmt.size())
          break;

        char Conv = Fmt[j];
        unsigned StarsBeforePtr = WidthStars + (PrecisionStar ? 1 : 0);

        if (Conv == 's') {
          unsigned PtrIdx = NextArg + StarsBeforePtr;
          if (PtrIdx < Call.getNumArgs()) {
            SVal PtrVal = State->getSVal(Call.getArgExpr(PtrIdx),
                                         C.getLocationContext());
            if (isSValTainted(State, PtrVal, UntrustedLenBufTag) &&
                !HasPrecision) {
              reportBug(C, Call.getOriginExpr(),
                        "Length-delimited buffer passed to %s; may read past end");
            }
          }
          NextArg += StarsBeforePtr + 1;
        } else {
          NextArg += StarsBeforePtr + 1;
        }
      }
      break; // only first StringLiteral format
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects length-delimited buffers used as NUL-terminated C strings",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "length_of": {"names": ["strlen"], "description": "function that computes the length of a NUL-terminated C string by scanning for a terminator"},
  "untrusted_size": {"names": ["ASN1_STRING_length", "ASN1_STRING_to_UTF8"], "description": "function or return value that provides a length for a length-delimited buffer"},
  "untrusted_data_accessor": {"names": ["ASN1_STRING_get0_data"], "description": "function that returns a pointer to raw, length-delimited data that may not be NUL-terminated"},
  "allocator": {"names": ["ASN1_STRING_to_UTF8"], "description": "function that allocates memory and writes the pointer through an output parameter or returns it"},
  "deallocator": {"names": ["OPENSSL_free"], "description": "function that frees memory or an object; pointer must not be used afterwards"},
  "error_setter": {"names": ["failf", "infof"], "description": "printf-style function that records or reports an error/info message; format arguments must be valid C strings unless length-bounded"}
}
*/
