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

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/Support/Casting.h"

#include <optional>

using namespace clang;
using namespace ento;

// Program state maps to track the capacity requested from a reallocator and the
// buffer regions that will be written to.
REGISTER_MAP_WITH_PROGRAMSTATE(AccumCapacityMap, const MemRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(BufferCapacityMap, const MemRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(BufferStartOffsetMap, const MemRegion *, SVal)

namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Buffer Overflow", "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  bool isReallocator(const CallEvent &Call) const;
  bool isBufferCopy(const CallEvent &Call) const;
  bool isMemset(const CallEvent &Call) const;

  bool handleBufferSetup(const BinaryOperator *BO, CheckerContext &C) const;
  bool computeOffset(const MemRegion *MR, SVal &Offset, CheckerContext &C) const;
  void checkWrite(const MemRegion *DestR, SVal WriteSize, const Stmt *S,
                  CheckerContext &C) const;
  void reportOverflow(const Stmt *S, CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isReallocator(const CallEvent &Call) const {
  return knighter::callIsRole(Call, "reallocator");
}

bool SAGenTestChecker::isBufferCopy(const CallEvent &Call) const {
  return knighter::callIsRole(Call, "buffer_copy");
}

bool SAGenTestChecker::isMemset(const CallEvent &Call) const {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    return ID->getName() == "memset";
  }
  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (isReallocator(Call)) {
    if (Call.getNumArgs() < 2)
      return;
    SVal AccumVal = Call.getArgSVal(0);
    const MemRegion *AccumR = AccumVal.getAsRegion();
    if (!AccumR)
      return;
    AccumR = AccumR->getBaseRegion();
    unsigned LastIdx = Call.getNumArgs() - 1;
    SVal Capacity = Call.getArgSVal(LastIdx);
    if (Capacity.isUnknown())
      return;
    State = State->set<AccumCapacityMap>(AccumR, Capacity);
    C.addTransition(State);
    return;
  }

  if (isBufferCopy(Call) || isMemset(Call)) {
    if (Call.getNumArgs() < 3)
      return;
    SVal DestVal = Call.getArgSVal(0);
    const MemRegion *DestR = DestVal.getAsRegion();
    if (!DestR)
      return;
    SVal WriteSize = Call.getArgSVal(2);
    if (WriteSize.isUnknown())
      return;
    checkWrite(DestR, WriteSize, Call.getOriginExpr(), C);
    return;
  }
}

bool SAGenTestChecker::handleBufferSetup(const BinaryOperator *BO,
                                         CheckerContext &C) const {
  if (BO->getOpcode() != BO_Assign)
    return false;
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  const auto *Add = dyn_cast<BinaryOperator>(RHS);
  if (!Add || Add->getOpcode() != BO_Add)
    return false;

  const Expr *LHS = Add->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS2 = Add->getRHS()->IgnoreParenImpCasts();
  const MemberExpr *ME = nullptr;
  const Expr *OffsetExpr = nullptr;
  if (const auto *M = dyn_cast<MemberExpr>(LHS)) {
    ME = M;
    OffsetExpr = RHS2;
  } else if (const auto *M = dyn_cast<MemberExpr>(RHS2)) {
    ME = M;
    OffsetExpr = LHS;
  }
  if (!ME || !OffsetExpr)
    return false;

  ProgramStateRef State = C.getState();
  const Expr *BaseExpr = ME->getBase()->IgnoreParenImpCasts();
  SVal BaseVal = State->getSVal(BaseExpr, C.getLocationContext());
  const MemRegion *AccumR = BaseVal.getAsRegion();
  if (!AccumR)
    return false;
  AccumR = AccumR->getBaseRegion();

  const SVal *Capacity = State->get<AccumCapacityMap>(AccumR);
  if (!Capacity)
    return false;

  SVal BufVal = State->getSVal(ME, C.getLocationContext());
  const MemRegion *BaseR = BufVal.getAsRegion();
  if (!BaseR)
    return false;
  BaseR = BaseR->getBaseRegion();

  SVal StartOffset = State->getSVal(OffsetExpr, C.getLocationContext());
  if (StartOffset.isUnknown())
    return false;

  State = State->set<BufferCapacityMap>(BaseR, *Capacity);
  State = State->set<BufferStartOffsetMap>(BaseR, StartOffset);
  C.addTransition(State);
  return true;
}

bool SAGenTestChecker::computeOffset(const MemRegion *MR, SVal &Offset,
                                     CheckerContext &C) const {
  if (const auto *ER = dyn_cast<ElementRegion>(MR)) {
    Offset = ER->getIndex();
    return true;
  }
  // If it's a base region, offset is 0.
  if (isa<SymbolicRegion>(MR) || isa<VarRegion>(MR)) {
    Offset = C.getSValBuilder().makeIntVal(0, C.getASTContext().IntTy);
    return true;
  }
  // For other subregions, try to get the offset.
  if (const auto *SR = dyn_cast<SubRegion>(MR)) {
    Offset = C.getSValBuilder().makeIntVal(SR->getAsOffset().getOffset(),
                                           C.getASTContext().IntTy);
    return true;
  }
  return false;
}

void SAGenTestChecker::checkWrite(const MemRegion *DestR, SVal WriteSize,
                                  const Stmt *S, CheckerContext &C) const {
  const MemRegion *BaseR = DestR->getBaseRegion();
  if (!BaseR)
    return;
  ProgramStateRef State = C.getState();
  const SVal *Capacity = State->get<BufferCapacityMap>(BaseR);
  if (!Capacity)
    return;
  const SVal *StartOffset = State->get<BufferStartOffsetMap>(BaseR);
  if (!StartOffset)
    return;

  SVal Offset;
  if (!computeOffset(DestR, Offset, C))
    return;

  SValBuilder &SVB = C.getSValBuilder();
  ASTContext &AC = C.getASTContext();
  QualType IntTy = AC.IntTy;

  SVal RelOffset = SVB.evalBinOp(State, BO_Sub, Offset, *StartOffset, IntTy);
  if (RelOffset.isUnknown())
    return;

  SVal Total = SVB.evalBinOp(State, BO_Add, RelOffset, WriteSize, IntTy);
  if (Total.isUnknown())
    return;

  SVal Cond = SVB.evalBinOp(State, BO_GT, Total, *Capacity, AC.BoolTy);
  if (Cond.isUnknown())
    return;

  if (std::optional<NonLoc> CondNL = Cond.getAs<NonLoc>()) {
    if (State->assume(*CondNL, true)) {
      reportOverflow(S, C);
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  const Expr *E = dyn_cast<Expr>(S);
  if (E) {
    if (const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts())) {
      if (handleBufferSetup(BO, C))
        return;
    }
  }

  const MemRegion *LocR = Loc.getAsRegion();
  if (!LocR)
    return;
  const MemRegion *BaseR = LocR->getBaseRegion();
  if (!BaseR)
    return;
  ProgramStateRef State = C.getState();
  if (!State->get<BufferCapacityMap>(BaseR))
    return;

  // Compute write size from the type of the location.
  QualType Ty;
  if (E) {
    if (const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts())) {
      if (BO->getOpcode() == BO_Assign) {
        Ty = BO->getLHS()->getType();
      }
    }
  }
  if (Ty.isNull()) {
    Ty = C.getASTContext().CharTy;
  }
  uint64_t Size = C.getASTContext().getTypeSize(Ty) / 8;
  if (Size == 0)
    Size = 1;
  SVal WriteSize =
      C.getSValBuilder().makeIntVal(Size, C.getASTContext().IntTy);
  checkWrite(LocR, WriteSize, S, C);
}

void SAGenTestChecker::reportOverflow(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Buffer overflow: allocated capacity is too small for subsequent writes",
      N);
  if (S)
    report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects buffer overflows where reallocator capacity is too small for "
      "later writes",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "reallocator": {"names": ["sqlite3StrAccumEnlargeIfNeeded"], "description": "Ensures a buffer has at least the requested number of bytes available; returns nonzero on failure."},
  "buffer_copy": {"names": ["memcpy", "memmove"], "description": "Copies a specified number of bytes from a source to a destination buffer."}
}
*/
