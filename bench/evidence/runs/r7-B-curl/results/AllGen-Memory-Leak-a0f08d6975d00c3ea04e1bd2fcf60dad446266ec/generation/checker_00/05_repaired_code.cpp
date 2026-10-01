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

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks memory regions that have been fully zeroed by memset/bzero/clear-like
// functions.  The target bug is releasing an embedded resource after its
// containing struct has been zeroed.
REGISTER_SET_WITH_PROGRAMSTATE(ZeroedRegions, const MemRegion *)

namespace {

struct ZeroingFunction {
  const char *Name;
  unsigned PtrParam;
  int ValueParam;  // -1 if no value check is needed
  int SizeParam;   // -1 if the whole region is assumed zeroed
  bool AssumeFull; // true for clear-like functions
};

struct ReleaseFunction {
  const char *Name;
  unsigned PtrParam;
};

static const ZeroingFunction ZeroingFuncs[] = {
    {"memset", 0, 1, 2, false},
    {"__builtin_memset", 0, 1, 2, false},
    {"bzero", 0, -1, 1, false},
    {"explicit_bzero", 0, -1, 1, false},
    {"cf_h2_proxy_ctx_clear", 0, -1, -1, true},
};

static const ReleaseFunction ReleaseFuncs[] = {
    {"Curl_peer_unlink", 0},
    {"Curl_bufq_free", 0},
    {"free", 0},
    {"kfree", 0},
};

static bool callNameIs(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  if (const IdentifierInfo *II = Call.getCalleeIdentifier())
    return II->getName() == Name;

  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, Name, C);
}

static bool isFullZeroing(const CallEvent &Call, const MemRegion *R,
                          const ZeroingFunction &ZF, CheckerContext &C) {
  if (ZF.AssumeFull)
    return true;

  if (ZF.SizeParam < 0)
    return false;

  const Expr *SizeE = Call.getArgExpr(ZF.SizeParam);
  if (!SizeE)
    return false;

  llvm::APSInt SizeVal;
  if (!EvaluateExprToInt(SizeVal, SizeE, C))
    return false;

  if (SizeVal.isNegative())
    return false;

  const TypedRegion *TR = llvm::dyn_cast<TypedRegion>(R);
  if (!TR)
    return false;

  QualType Ty = TR->getLocationType();
  if (Ty.isNull() || Ty->isIncompleteType())
    return false;

  CharUnits RegionSize = C.getASTContext().getTypeSizeInChars(Ty);
  uint64_t Size = SizeVal.getLimitedValue();
  uint64_t Needed = RegionSize.getQuantity();
  return Size >= Needed;
}

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Resource Unlink After Zeroing",
                       "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  for (const auto &ZF : ZeroingFuncs) {
    if (!callNameIs(Call, ZF.Name, C))
      continue;

    if (ZF.PtrParam >= Call.getNumArgs())
      return;

    SVal PtrVal = Call.getArgSVal(ZF.PtrParam);
    const MemRegion *R = PtrVal.getAsRegion();
    if (!R)
      return;

    if (ZF.ValueParam >= 0) {
      const Expr *ValE = Call.getArgExpr(ZF.ValueParam);
      if (!ValE)
        return;

      llvm::APSInt Val;
      if (!EvaluateExprToInt(Val, ValE, C))
        return;
      if (!Val.isZero())
        return;
    }

    if (!isFullZeroing(Call, R, ZF, C))
      return;

    State = State->add<ZeroedRegions>(R);
    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  for (const auto &RF : ReleaseFuncs) {
    if (!callNameIs(Call, RF.Name, C))
      continue;

    if (RF.PtrParam >= Call.getNumArgs())
      return;

    SVal ArgVal = Call.getArgSVal(RF.PtrParam);
    const MemRegion *R = ArgVal.getAsRegion();
    if (!R)
      return;

    const MemRegion *Base = R->getBaseRegion();
    if (R == Base)
      return;

    if (State->contains<ZeroedRegions>(R) ||
        State->contains<ZeroedRegions>(Base)) {
      ExplodedNode *Err = C.generateNonFatalErrorNode();
      if (!Err)
        return;

      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Unlinking embedded resource after containing struct was zeroed",
          Err);
      Report->addRange(Call.getSourceRange());
      C.emitReport(std::move(Report));
    }
    return;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects releasing embedded resources after containing struct was zeroed",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
