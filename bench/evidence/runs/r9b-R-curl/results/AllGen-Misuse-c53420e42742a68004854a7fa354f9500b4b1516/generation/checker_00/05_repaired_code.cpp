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

REGISTER_MAP_WITH_PROGRAMSTATE(LengthDelimitedMap, const MemRegion *, bool)

namespace {
class SAGenTestChecker : public Checker<eval::Call, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Length-delimited buffer used as NUL-terminated string",
                       "String API misuse")) {}

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C, const char *Msg) const;
};
} // end anonymous namespace

bool SAGenTestChecker::evalCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
  if (!CE)
    return false;

  SValBuilder &SVB = C.getSValBuilder();
  const LocationContext *LCtx = C.getLocationContext();
  unsigned Count = C.blockCount();

  if (knighter::callIsRole(Call, "parser_input")) {
    DefinedSVal RetVal =
        SVB.getConjuredHeapSymbolVal(CE, LCtx, Count).castAs<DefinedSVal>();
    const MemRegion *MR = RetVal.getAsRegion();
    if (MR) {
      MR = MR->getBaseRegion();
      State = State->set<LengthDelimitedMap>(MR, true);
    }
    State = State->BindExpr(CE, C.getLocationContext(), RetVal);
    C.addTransition(State);
    return true;
  }

  if (knighter::callIsRole(Call, "allocator")) {
    // Find the out-parameter: the first argument that is a pointer to a pointer.
    int OutIdx = -1;
    for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
      QualType Ty = CE->getArg(i)->getType();
      if (Ty->isPointerType() && Ty->getPointeeType()->isPointerType()) {
        OutIdx = i;
        break;
      }
    }
    if (OutIdx < 0)
      return false;

    SVal OutVal = Call.getArgSVal(OutIdx);
    if (!OutVal.getAs<Loc>())
      return false;

    // Conjure a new heap region for the allocated buffer.
    DefinedSVal NewPtr =
        SVB.getConjuredHeapSymbolVal(CE, LCtx, Count).castAs<DefinedSVal>();
    const MemRegion *NewMR = NewPtr.getAsRegion();
    if (NewMR) {
      NewMR = NewMR->getBaseRegion();
      State = State->set<LengthDelimitedMap>(NewMR, true);
    }

    // Bind the new pointer to the location pointed by the out-parameter.
    Loc OutLoc = OutVal.castAs<Loc>();
    State = State->bindLoc(OutLoc, NewPtr, C.getLocationContext());

    // Return a symbolic integer for the length.
    SVal RetVal = SVB.conjureSymbolVal(nullptr, CE, LCtx, CE->getType(), Count);
    State = State->BindExpr(CE, C.getLocationContext(), RetVal);

    C.addTransition(State);
    return true;
  }

  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (knighter::callIsRole(Call, "length_of")) {
    if (Call.getNumArgs() < 1)
      return;
    const Expr *ArgE = Call.getArgExpr(0);
    if (!ArgE)
      return;
    const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    const bool *IsLenDelim = State->get<LengthDelimitedMap>(MR);
    if (IsLenDelim && *IsLenDelim) {
      reportBug(Call, C,
                "Length-delimited buffer used as NUL-terminated string");
    }
    return;
  }

  if (knighter::callIsRole(Call, "error_setter")) {
    // Find the format string argument (first StringLiteral).
    int FmtIdx = -1;
    const StringLiteral *FmtSL = nullptr;
    for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
      const Expr *ArgE = Call.getArgExpr(i);
      if (!ArgE)
        continue;
      if (const StringLiteral *SL =
              dyn_cast<StringLiteral>(ArgE->IgnoreImpCasts())) {
        FmtIdx = i;
        FmtSL = SL;
        break;
      }
    }
    if (FmtIdx < 0 || !FmtSL)
      return;

    // Only interested in unsafe %s formatting.
    if (!FmtSL->getString().contains("%s"))
      return;

    // Check arguments after the format string.
    for (unsigned j = FmtIdx + 1; j < Call.getNumArgs(); ++j) {
      const Expr *ArgE = Call.getArgExpr(j);
      if (!ArgE)
        continue;
      const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
      if (!MR)
        continue;
      MR = MR->getBaseRegion();
      const bool *IsLenDelim = State->get<LengthDelimitedMap>(MR);
      if (IsLenDelim && *IsLenDelim) {
        reportBug(Call, C, "Length-delimited buffer formatted with %s");
        return;
      }
    }
  }
}

void SAGenTestChecker::reportBug(const CallEvent &Call, CheckerContext &C,
                                 const char *Msg) const {
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
      "Detects length-delimited buffers used as NUL-terminated strings",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["ASN1_STRING_get0_data"], "description": "returns a pointer to raw certificate field bytes"},
  "untrusted_size": {"names": ["ASN1_STRING_length"], "description": "returns the explicit length of those bytes"},
  "length_of": {"names": ["strlen"], "description": "computes string length by scanning for a NUL terminator; unsafe for length-delimited buffers"},
  "error_setter": {"names": ["failf", "infof"], "description": "printf-style function that records an error/info message; its %s format specifier requires a NUL-terminated string"},
  "allocator": {"names": ["ASN1_STRING_to_UTF8"], "description": "allocates a new buffer through an out-parameter and returns its length"},
  "deallocator": {"names": ["OPENSSL_free"], "description": "frees a previously allocated buffer"}
}
*/
