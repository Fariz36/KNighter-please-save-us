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

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps for capacity, offset, and buffer-to-context mapping.
REGISTER_MAP_WITH_PROGRAMSTATE(CapacityMap, const MemRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(OffsetMap, const MemRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(BufferToContextMap, const MemRegion *, const MemRegion *)

namespace {

// Helper: is the given type a character type?
static bool isCharType(QualType Ty) {
  return Ty->isSpecificBuiltinType(BuiltinType::Char_S) ||
         Ty->isSpecificBuiltinType(BuiltinType::Char_U) ||
         Ty->isSpecificBuiltinType(BuiltinType::SChar) ||
         Ty->isSpecificBuiltinType(BuiltinType::UChar);
}

// Helper: extract the "size" argument from a call.  We iterate backwards and
// pick the last integer argument that is not a character (when skipChar is true).
static SVal getSizeArg(const CallEvent &Call, ASTContext &AC, bool skipChar) {
  for (int i = Call.getNumArgs() - 1; i >= 0; --i) {
    const Expr *Arg = Call.getArgExpr(i);
    if (!Arg)
      continue;
    QualType Ty = Arg->getType();
    if (!Ty->isIntegerType())
      continue;
    if (skipChar && isCharType(Ty))
      continue;
    return Call.getArgSVal(i);
  }
  // Fallback: last integer argument even if it is a character type.
  for (int i = Call.getNumArgs() - 1; i >= 0; --i) {
    const Expr *Arg = Call.getArgExpr(i);
    if (!Arg)
      continue;
    QualType Ty = Arg->getType();
    if (Ty->isIntegerType())
      return Call.getArgSVal(i);
  }
  return SVal();
}

// Helper: recursively search an expression for a sub-expression whose base
// memory region is a key in CapacityMap.  Returns the context region if found.
static const MemRegion *findContextRegion(const Expr *E, CheckerContext &C,
                                          ProgramStateRef State) {
  if (!E)
    return nullptr;
  SVal V = State->getSVal(E, C.getLocationContext());
  if (const MemRegion *MR = V.getAsRegion()) {
    const MemRegion *Base = MR->getBaseRegion();
    if (Base && State->get<CapacityMap>(Base)) {
      return Base;
    }
  }
  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child)) {
      if (const MemRegion *Res = findContextRegion(ChildE, C, State))
        return Res;
    }
  }
  return nullptr;
}

class SAGenTestChecker : public Checker<check::PreCall, check::Bind, check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Buffer Overflow", "Memory Safety")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  void reportOverflow(CheckerContext &C, const MemRegion *CtxReg, SVal Capacity,
                      SVal NewOffset) const;
};

} // end anonymous namespace

//----------------------------------------------------------------------
// checkPreCall
//----------------------------------------------------------------------
void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // 1) Reallocator: set capacity and reset offset.
  if (knighter::callIsRole(Call, "reallocator")) {
    if (Call.getNumArgs() < 1)
      return;
    SVal CtxVal = Call.getArgSVal(0);
    const MemRegion *CtxReg = CtxVal.getAsRegion();
    if (!CtxReg)
      return;
    CtxReg = CtxReg->getBaseRegion();
    if (!CtxReg)
      return;

    SVal SizeSVal = getSizeArg(Call, C.getASTContext(), false);
    if (SizeSVal.isUnknown())
      return;

    State = State->set<CapacityMap>(CtxReg, SizeSVal);
    SVal Zero = C.getSValBuilder().makeIntVal(0, C.getASTContext().IntTy);
    State = State->set<OffsetMap>(CtxReg, Zero);
    C.addTransition(State);
    return;
  }

  // 2) Buffer copy: update offset by the length argument.
  if (knighter::callIsRole(Call, "buffer_copy")) {
    if (Call.getNumArgs() < 1)
      return;
    SVal FirstArg = Call.getArgSVal(0);
    const MemRegion *FirstReg = FirstArg.getAsRegion();
    if (!FirstReg)
      return;
    FirstReg = FirstReg->getBaseRegion();
    if (!FirstReg)
      return;

    const MemRegion *CtxReg = nullptr;
    if (State->get<CapacityMap>(FirstReg)) {
      CtxReg = FirstReg;
    } else if (const MemRegion *const *Mapped =
                   State->get<BufferToContextMap>(FirstReg)) {
      CtxReg = *Mapped;
    }
    if (!CtxReg)
      return;

    SVal LengthSVal = getSizeArg(Call, C.getASTContext(), true);
    if (LengthSVal.isUnknown())
      return;

    const SVal *CapacitySVal = State->get<CapacityMap>(CtxReg);
    const SVal *OffsetSVal = State->get<OffsetMap>(CtxReg);
    if (!CapacitySVal || !OffsetSVal)
      return;

    SVal NewOffset = C.getSValBuilder().evalBinOp(
        State, BO_Add, *OffsetSVal, LengthSVal, C.getASTContext().IntTy);
    if (NewOffset.isUnknown())
      return;

    SVal OverflowCond = C.getSValBuilder().evalBinOp(
        State, BO_GT, NewOffset, *CapacitySVal, C.getASTContext().BoolTy);
    if (OverflowCond.isUnknown()) {
      State = State->set<OffsetMap>(CtxReg, NewOffset);
      C.addTransition(State);
      return;
    }

    if (auto Cond = OverflowCond.getAs<DefinedOrUnknownSVal>()) {
      ProgramStateRef TrueState, FalseState;
      std::tie(TrueState, FalseState) = State->assume(*Cond);
      if (TrueState) {
        reportOverflow(C, CtxReg, *CapacitySVal, NewOffset);
      }
    }
    State = State->set<OffsetMap>(CtxReg, NewOffset);
    C.addTransition(State);
    return;
  }
}

//----------------------------------------------------------------------
// checkBind: track pointer assignments to map concrete buffer regions
//            back to their capacity context.
//----------------------------------------------------------------------
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *LHS = nullptr;
  const Expr *RHS = nullptr;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp()) {
      LHS = BO->getLHS();
      RHS = BO->getRHS();
    }
  }
  if (!LHS || !RHS)
    return;
  if (!LHS->getType()->isPointerType())
    return;

  const MemRegion *CtxReg = findContextRegion(RHS, C, State);
  if (!CtxReg)
    return;

  const MemRegion *BufReg = Val.getAsRegion();
  if (!BufReg)
    return;
  BufReg = BufReg->getBaseRegion();
  if (!BufReg)
    return;

  State = State->set<BufferToContextMap>(BufReg, CtxReg);
  C.addTransition(State);
}

//----------------------------------------------------------------------
// checkLocation: track direct stores into the buffer.
//----------------------------------------------------------------------
void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (IsLoad)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *LocR = Loc.getAsRegion();
  if (!LocR)
    return;
  const MemRegion *BaseReg = LocR->getBaseRegion();
  if (!BaseReg)
    return;

  const MemRegion *const *CtxRegPtr = State->get<BufferToContextMap>(BaseReg);
  if (!CtxRegPtr)
    return;
  const MemRegion *CtxReg = *CtxRegPtr;
  if (!CtxReg)
    return;

  const SVal *CapacitySVal = State->get<CapacityMap>(CtxReg);
  const SVal *OffsetSVal = State->get<OffsetMap>(CtxReg);
  if (!CapacitySVal || !OffsetSVal)
    return;

  // Determine the size of the write from the LHS type.
  int WriteSize = 1;
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp()) {
      QualType Ty = BO->getLHS()->getType();
      if (Ty->isVoidType())
        return;
      WriteSize = C.getASTContext().getTypeSizeInChars(Ty).getQuantity();
    }
  } else if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->isIncrementDecrementOp()) {
      QualType Ty = UO->getSubExpr()->getType();
      if (Ty->isVoidType())
        return;
      WriteSize = C.getASTContext().getTypeSizeInChars(Ty).getQuantity();
    }
  }
  if (WriteSize <= 0)
    WriteSize = 1;

  SVal WriteSizeVal =
      C.getSValBuilder().makeIntVal(WriteSize, C.getASTContext().IntTy);
  SVal NewOffset = C.getSValBuilder().evalBinOp(
      State, BO_Add, *OffsetSVal, WriteSizeVal, C.getASTContext().IntTy);
  if (NewOffset.isUnknown())
    return;

  SVal OverflowCond = C.getSValBuilder().evalBinOp(
      State, BO_GT, NewOffset, *CapacitySVal, C.getASTContext().BoolTy);
  if (OverflowCond.isUnknown()) {
    State = State->set<OffsetMap>(CtxReg, NewOffset);
    C.addTransition(State);
    return;
  }

  if (auto Cond = OverflowCond.getAs<DefinedOrUnknownSVal>()) {
    ProgramStateRef TrueState, FalseState;
    std::tie(TrueState, FalseState) = State->assume(*Cond);
    if (TrueState) {
      reportOverflow(C, CtxReg, *CapacitySVal, NewOffset);
    }
  }
  State = State->set<OffsetMap>(CtxReg, NewOffset);
  C.addTransition(State);
}

//----------------------------------------------------------------------
// reportOverflow
//----------------------------------------------------------------------
void SAGenTestChecker::reportOverflow(CheckerContext &C,
                                      const MemRegion *CtxReg, SVal Capacity,
                                      SVal NewOffset) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Buffer overflow: write exceeds requested buffer capacity", N);
  C.emitReport(std::move(Report));
}

//===----------------------------------------------------------------------===//
// Checker Registration
//===----------------------------------------------------------------------===//
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects buffer overflows where writes exceed the capacity requested "
      "from a reallocator",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "reallocator": {
    "names": ["sqlite3StrAccumEnlargeIfNeeded"],
    "description": "Ensures/grows an output buffer to have at least the requested number of bytes available; the size argument is the guaranteed capacity for subsequent writes."
  },
  "buffer_copy": {
    "names": ["memcpy", "memmove", "memset", "sqlite3_str_append", "sqlite3_str_appendchar", "sqlite3_str_appendall"],
    "description": "Writes/copies a bounded number of bytes into a destination buffer or append-style output object; the length argument bounds the write."
  }
}
*/
