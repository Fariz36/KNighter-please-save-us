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
#include "llvm/Support/Casting.h"
#include "clang/Basic/OperatorKinds.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps to track buffer capacity, write offsets, and aliases.
REGISTER_MAP_WITH_PROGRAMSTATE(BufferCapacityMap, const MemRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(WriteOffsetMap, const MemRegion *, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(BufferObjectMap, const MemRegion *, const MemRegion *)

namespace {
class SAGenTestChecker : public Checker<check::PreCall, check::Location, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Buffer Overflow", "Memory Safety")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  const MemRegion *findBaseRegionInMap(const MemRegion *MR, ProgramStateRef State) const;
  void reportOverflow(const CallEvent *Call, const Stmt *S, CheckerContext &C) const;
};
} // end anonymous namespace

const MemRegion *SAGenTestChecker::findBaseRegionInMap(const MemRegion *MR, ProgramStateRef State) const {
  const MemRegion *Current = MR;
  while (Current) {
    if (State->get<BufferCapacityMap>(Current))
      return Current;
    const SubRegion *SR = dyn_cast<SubRegion>(Current);
    if (!SR)
      break;
    Current = SR->getSuperRegion();
  }
  return nullptr;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Allocator role: reserves capacity for a buffer.
  if (knighter::callIsRole(Call, "allocator")) {
    if (Call.getNumArgs() < 2) return;
    const Expr *BufExpr = Call.getArgExpr(0);
    if (!BufExpr) return;
    const MemRegion *BufObjRegion = getMemRegionFromExpr(BufExpr, C);
    if (!BufObjRegion) return;
    BufObjRegion = BufObjRegion->getBaseRegion();
    if (!BufObjRegion) return;

    const Expr *SizeExpr = Call.getArgExpr(1);
    if (!SizeExpr) return;
    SVal SizeVal = State->getSVal(SizeExpr, C.getLocationContext());

    State = State->set<BufferCapacityMap>(BufObjRegion, SizeVal);
    State = State->set<WriteOffsetMap>(BufObjRegion, 0);
    C.addTransition(State);
    return;
  }

  // Buffer copy role: writes a specified number of bytes into a destination.
  if (knighter::callIsRole(Call, "buffer_copy")) {
    unsigned NumArgs = Call.getNumArgs();
    if (NumArgs < 2) return;
    const Expr *DestExpr = Call.getArgExpr(0);
    if (!DestExpr) return;
    const MemRegion *DestRegion = getMemRegionFromExpr(DestExpr, C);
    if (!DestRegion) return;
    DestRegion = DestRegion->getBaseRegion();
    if (!DestRegion) return;

    const MemRegion *Key = findBaseRegionInMap(DestRegion, State);
    if (!Key) {
      if (const MemRegion * const *BufferObjPtr = State->get<BufferObjectMap>(DestRegion))
        Key = *BufferObjPtr;
    }
    if (!Key) return;

    const Expr *SizeExpr = Call.getArgExpr(NumArgs - 1);
    if (!SizeExpr) return;
    llvm::APSInt SizeInt;
    if (!EvaluateExprToInt(SizeInt, SizeExpr, C)) return;
    unsigned Size = SizeInt.getZExtValue();

    const unsigned *OffsetPtr = State->get<WriteOffsetMap>(Key);
    unsigned Offset = OffsetPtr ? *OffsetPtr : 0;
    unsigned NewOffset = Offset + Size;

    const SVal *CapPtr = State->get<BufferCapacityMap>(Key);
    if (!CapPtr) return;
    SVal Capacity = *CapPtr;

    // Check if the new offset definitely exceeds the reserved capacity.
    SValBuilder &SVB = C.getSValBuilder();
    SVal OffsetVal = SVB.makeIntVal(NewOffset, C.getASTContext().UnsignedIntTy);
    SVal Cond = SVB.evalBinOp(State, BO_GE, OffsetVal, Capacity, C.getASTContext().IntTy);
    if (Cond.isUnknown()) return;

    ProgramStateRef StTrue, StFalse;
    std::tie(StTrue, StFalse) = State->assume(Cond.castAs<DefinedOrUnknownSVal>());
    if (!StFalse) {
      reportOverflow(&Call, nullptr, C);
      return;
    }

    State = State->set<WriteOffsetMap>(Key, NewOffset);
    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (IsLoad) return;
  ProgramStateRef State = C.getState();
  const MemRegion *DestRegion = Loc.getAsRegion();
  if (!DestRegion) return;
  DestRegion = DestRegion->getBaseRegion();
  if (!DestRegion) return;

  const MemRegion *Key = findBaseRegionInMap(DestRegion, State);
  if (!Key) {
    if (const MemRegion * const *BufferObjPtr = State->get<BufferObjectMap>(DestRegion))
      Key = *BufferObjPtr;
  }
  if (!Key) return;

  const unsigned *OffsetPtr = State->get<WriteOffsetMap>(Key);
  unsigned Offset = OffsetPtr ? *OffsetPtr : 0;

  unsigned Size = 1;
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp()) {
      QualType Ty = BO->getRHS()->getType();
      if (!Ty.isNull()) {
        Size = C.getASTContext().getTypeSizeInChars(Ty).getQuantity();
      }
    }
  } else if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->isIncrementDecrementOp()) {
      QualType Ty = UO->getSubExpr()->getType();
      if (!Ty.isNull()) {
        Size = C.getASTContext().getTypeSizeInChars(Ty).getQuantity();
      }
    }
  }

  unsigned NewOffset = Offset + Size;

  const SVal *CapPtr = State->get<BufferCapacityMap>(Key);
  if (!CapPtr) return;
  SVal Capacity = *CapPtr;

  SValBuilder &SVB = C.getSValBuilder();
  SVal OffsetVal = SVB.makeIntVal(NewOffset, C.getASTContext().UnsignedIntTy);
  SVal Cond = SVB.evalBinOp(State, BO_GE, OffsetVal, Capacity, C.getASTContext().IntTy);
  if (Cond.isUnknown()) return;

  ProgramStateRef StTrue, StFalse;
  std::tie(StTrue, StFalse) = State->assume(Cond.castAs<DefinedOrUnknownSVal>());
  if (!StFalse) {
    reportOverflow(nullptr, S, C);
    return;
  }

  State = State->set<WriteOffsetMap>(Key, NewOffset);
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *H = Val.getAsRegion();
  if (!H) return;
  H = H->getBaseRegion();
  if (!H) return;

  const Expr *RHS = nullptr;
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp()) RHS = BO->getRHS();
  } else if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    if (DS->isSingleDecl()) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DS->getSingleDecl())) {
        if (VD->hasInit()) RHS = VD->getInit();
      }
    }
  }
  if (!RHS) return;
  RHS = RHS->IgnoreParenCasts();

  const MemberExpr *ME = findSpecificTypeInChildren<MemberExpr>(RHS);
  if (!ME) return;

  const Expr *BaseE = ME->getBase();
  SVal BaseVal = State->getSVal(BaseE, C.getLocationContext());
  const MemRegion *SReg = BaseVal.getAsRegion();
  if (!SReg) return;
  SReg = SReg->getBaseRegion();
  if (!SReg) return;

  State = State->set<BufferObjectMap>(H, SReg);
  C.addTransition(State);
}

void SAGenTestChecker::reportOverflow(const CallEvent *Call, const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Buffer overflow: write exceeds reserved capacity", N);
  if (Call) {
    Report->addRange(Call->getSourceRange());
  } else if (S) {
    Report->addRange(S->getSourceRange());
  }
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects buffer overflow when writes exceed reserved capacity",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {
    "names": ["sqlite3StrAccumEnlargeIfNeeded"],
    "description": "ensures/reserves capacity for a buffer; its size argument is the number of bytes to reserve for subsequent writes"
  },
  "buffer_copy": {
    "names": ["memcpy", "memset", "memmove"],
    "description": "copies or writes a specified number of bytes into a destination buffer"
  }
}
*/
