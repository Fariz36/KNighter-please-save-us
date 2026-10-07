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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps to track buffer sizes and writes.
REGISTER_MAP_WITH_PROGRAMSTATE(PendingReallocMap, const MemRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(BufferSizeMap, const MemRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(BufferStartMap, const MemRegion *, SVal)
REGISTER_MAP_WITH_PROGRAMSTATE(BufferMaxMap, const MemRegion *, SVal)

namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::Bind, check::Location> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Buffer Overflow", "Memory Error")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

private:
  void reportOverflow(const MemRegion *BufferRegion, CheckerContext &C, const Stmt *S) const;
};

} // end anonymous namespace

// Helper to get offset from a MemRegion.
static bool getRegionOffset(const MemRegion *MR, SVal &Offset, CheckerContext &C) {
  if (!MR) return false;
  RegionOffset RO = MR->getAsOffset();
  Offset = C.getSValBuilder().makeIntVal(RO.getOffset(), C.getASTContext().getSizeType());
  return true;
}

// Helper to extract the RHS expression from a store statement.
static const Expr *getRHSFromStore(const Stmt *StoreE) {
  if (!StoreE) return nullptr;
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(StoreE)) {
    if (BO->isAssignmentOp()) {
      return BO->getRHS();
    }
  } else if (const DeclStmt *DS = dyn_cast<DeclStmt>(StoreE)) {
    if (DS->isSingleDecl()) {
      const VarDecl *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
      if (VD && VD->hasInit()) {
        return VD->getInit();
      }
    }
  }
  return nullptr;
}

// Helper to find a MemberExpr whose base object is a pending reallocator target.
static const MemberExpr *findMemberExprFromPending(const Expr *E, ProgramStateRef State,
                                                   CheckerContext &C, SVal &SizeOut) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const MemberExpr *ME = dyn_cast<MemberExpr>(E)) {
    SVal BaseVal = State->getSVal(ME->getBase(), C.getLocationContext());
    if (const MemRegion *BaseReg = BaseVal.getAsRegion()) {
      BaseReg = BaseReg->getBaseRegion();
      if (const SVal *Size = State->get<PendingReallocMap>(BaseReg)) {
        SizeOut = *Size;
        return ME;
      }
    }
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (const MemberExpr *ME = findMemberExprFromPending(BO->getLHS(), State, C, SizeOut))
      return ME;
    if (const MemberExpr *ME = findMemberExprFromPending(BO->getRHS(), State, C, SizeOut))
      return ME;
  } else if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    return findMemberExprFromPending(UO->getSubExpr(), State, C, SizeOut);
  } else if (const CastExpr *CE = dyn_cast<CastExpr>(E)) {
    return findMemberExprFromPending(CE->getSubExpr(), State, C, SizeOut);
  } else if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    return findMemberExprFromPending(ASE->getBase(), State, C, SizeOut);
  } else if (const ConditionalOperator *CO = dyn_cast<ConditionalOperator>(E)) {
    if (const MemberExpr *ME = findMemberExprFromPending(CO->getTrueExpr(), State, C, SizeOut))
      return ME;
    if (const MemberExpr *ME = findMemberExprFromPending(CO->getFalseExpr(), State, C, SizeOut))
      return ME;
  }
  return nullptr;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Handle reallocator calls: record the requested size.
  if (knighter::callIsRole(Call, "reallocator")) {
    if (Call.getNumArgs() < 2) return;
    SVal ObjVal = Call.getArgSVal(0);
    const MemRegion *ObjReg = ObjVal.getAsRegion();
    if (!ObjReg) return;
    ObjReg = ObjReg->getBaseRegion();
    SVal SizeVal = Call.getArgSVal(1);
    State = State->set<PendingReallocMap>(ObjReg, SizeVal);
    C.addTransition(State);
    return;
  }

  // Handle bulk writes: memset, memcpy, memmove.
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee) return;
  StringRef Name = Callee->getName();
  if (Name == "memset" || Name == "memcpy" || Name == "memmove") {
    if (Call.getNumArgs() < 3) return;
    SVal DestVal = Call.getArgSVal(0);
    const MemRegion *DestReg = DestVal.getAsRegion();
    if (!DestReg) return;
    const MemRegion *BaseReg = DestReg->getBaseRegion();
    const SVal *SizePtr = State->get<BufferSizeMap>(BaseReg);
    if (!SizePtr) return; // Not tracking this buffer.

    SVal Offset;
    if (!getRegionOffset(DestReg, Offset, C)) return;

    SVal WriteSize = Call.getArgSVal(2);
    SValBuilder &SVB = C.getSValBuilder();
    ASTContext &ACtx = C.getASTContext();
    SVal EndOffset = SVB.evalBinOp(State, BO_Add, Offset, WriteSize, ACtx.getSizeType());

    const SVal *StartPtr = State->get<BufferStartMap>(BaseReg);
    SVal Start;
    if (StartPtr) {
      Start = *StartPtr;
    } else {
      Start = Offset;
      State = State->set<BufferStartMap>(BaseReg, Start);
    }

    SVal Diff = SVB.evalBinOp(State, BO_Sub, EndOffset, Start, ACtx.getSizeType());
    SVal Size = *SizePtr;
    SVal Cond = SVB.evalBinOp(State, BO_GT, Diff, Size, ACtx.BoolTy);

    if (auto CondVal = Cond.getAs<DefinedOrUnknownSVal>()) {
      ProgramStateRef StTrue, StFalse;
      std::tie(StTrue, StFalse) = State->assume(*CondVal);
      if (StTrue) {
        reportOverflow(BaseReg, C, Call.getOriginExpr());
      }
    }

    State = State->set<BufferMaxMap>(BaseReg, EndOffset);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Expr *RHS = getRHSFromStore(StoreE);
  if (!RHS) return;

  SVal Size;
  const MemberExpr *ME = findMemberExprFromPending(RHS, State, C, Size);
  if (!ME) return;

  // The bound value points to the enlarged buffer.
  const MemRegion *BufferReg = Val.getAsRegion();
  if (!BufferReg) return;
  BufferReg = BufferReg->getBaseRegion();

  // Associate the buffer region with the requested size.
  State = State->set<BufferSizeMap>(BufferReg, Size);
  State = State->remove<BufferStartMap>(BufferReg);
  State = State->remove<BufferMaxMap>(BufferReg);

  // Remove the object from pending map.
  SVal BaseVal = State->getSVal(ME->getBase(), C.getLocationContext());
  if (const MemRegion *BaseReg = BaseVal.getAsRegion()) {
    BaseReg = BaseReg->getBaseRegion();
    State = State->remove<PendingReallocMap>(BaseReg);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  if (IsLoad) return; // Only stores.

  ProgramStateRef State = C.getState();
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR) return;
  const MemRegion *BaseReg = MR->getBaseRegion();
  const SVal *SizePtr = State->get<BufferSizeMap>(BaseReg);
  if (!SizePtr) return; // Not tracking this buffer.

  SVal Offset;
  if (!getRegionOffset(MR, Offset, C)) return;

  QualType Ty;
  if (const TypedValueRegion *TVR = dyn_cast<TypedValueRegion>(MR)) {
    Ty = TVR->getValueType();
  } else {
    Ty = C.getASTContext().CharTy;
  }
  CharUnits SizeInChars = C.getASTContext().getTypeSizeInChars(Ty);
  SVal WriteSize = C.getSValBuilder().makeIntVal(SizeInChars.getQuantity(), C.getASTContext().getSizeType());

  const SVal *StartPtr = State->get<BufferStartMap>(BaseReg);
  SVal Start;
  if (StartPtr) {
    Start = *StartPtr;
  } else {
    Start = Offset;
    State = State->set<BufferStartMap>(BaseReg, Start);
  }

  SValBuilder &SVB = C.getSValBuilder();
  ASTContext &ACtx = C.getASTContext();
  SVal EndOffset = SVB.evalBinOp(State, BO_Add, Offset, WriteSize, ACtx.getSizeType());
  SVal Diff = SVB.evalBinOp(State, BO_Sub, EndOffset, Start, ACtx.getSizeType());
  SVal Size = *SizePtr;
  SVal Cond = SVB.evalBinOp(State, BO_GT, Diff, Size, ACtx.BoolTy);

  if (auto CondVal = Cond.getAs<DefinedOrUnknownSVal>()) {
    ProgramStateRef StTrue, StFalse;
    std::tie(StTrue, StFalse) = State->assume(*CondVal);
    if (StTrue) {
      reportOverflow(BaseReg, C, S);
    }
  }

  State = State->set<BufferMaxMap>(BaseReg, EndOffset);
  C.addTransition(State);
}

void SAGenTestChecker::reportOverflow(const MemRegion *BufferRegion, CheckerContext &C, const Stmt *S) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Buffer overflow: write exceeds reallocator size argument", N);
  if (S) {
    Report->addRange(S->getSourceRange());
  }
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects buffer overflows when writes exceed the size argument of a reallocator",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "reallocator": {
    "names": ["sqlite3StrAccumEnlargeIfNeeded"],
    "description": "enlarges a buffer contained in the object pointed to by its first argument to hold at least the given number of additional bytes"
  }
}
*/
