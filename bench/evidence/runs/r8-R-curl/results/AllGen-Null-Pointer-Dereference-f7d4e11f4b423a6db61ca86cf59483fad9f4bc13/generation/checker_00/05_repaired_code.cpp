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

REGISTER_MAP_WITH_PROGRAMSTATE(LengthValidatedMap, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(DataCheckedMap, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(RetainedUncheckedMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker
    : public Checker<check::BranchCondition, check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL check", "Null Dereference")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                 CheckerContext &C) const;

private:
  void reportMissingNullCheck(const Stmt *S, CheckerContext &C) const;
  void reportRetainedDescriptor(const Stmt *S, CheckerContext &C) const;
};

// Return the base region of the object pointed to by the base expression of
// a member access. For example, for `blob->data`, this returns the region of
// the object pointed to by `blob`.
static const MemRegion *getBaseRegionFromMemberBase(const MemberExpr *ME,
                                                    CheckerContext &C) {
  if (!ME)
    return nullptr;

  const Expr *Base = ME->getBase();
  if (!Base)
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(Base, C);
  if (!MR)
    return nullptr;

  return MR->getBaseRegion();
}

// Recursively walk a condition and mark descriptor regions whose length or
// data pointer fields appear in the condition.
static void markValidatedFields(const Stmt *S, CheckerContext &C,
                                ProgramStateRef &State) {
  if (!S)
    return;

  if (const auto *ME = dyn_cast<MemberExpr>(S)) {
    const ValueDecl *VD = ME->getMemberDecl();
    if (knighter::declIsRole(VD, "length_of")) {
      if (const MemRegion *Base = getBaseRegionFromMemberBase(ME, C))
        State = State->set<LengthValidatedMap>(Base, true);
    } else if (knighter::declIsRole(VD, "data_pointer")) {
      if (const MemRegion *Base = getBaseRegionFromMemberBase(ME, C))
        State = State->set<DataCheckedMap>(Base, true);
    }
  }

  for (const Stmt *Child : S->children()) {
    if (Child)
      markValidatedFields(Child, C, State);
  }
}

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  markValidatedFields(Condition, C, State);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "buffer_copy"))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
    const Expr *Arg = Call.getArgExpr(I);
    if (!Arg)
      continue;

    const Expr *ArgE = Arg->IgnoreParenImpCasts();
    const auto *ME = dyn_cast<MemberExpr>(ArgE);
    if (!ME)
      continue;

    if (!knighter::declIsRole(ME->getMemberDecl(), "data_pointer"))
      continue;

    const MemRegion *Base = getBaseRegionFromMemberBase(ME, C);
    if (!Base)
      continue;

    const bool *LenValid = State->get<LengthValidatedMap>(Base);
    const bool *DataChecked = State->get<DataCheckedMap>(Base);

    if (LenValid && *LenValid && (!DataChecked || !*DataChecked)) {
      reportMissingNullCheck(Arg, C);
      break;
    }
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  if (!StoreE)
    return;

  const auto *BO = dyn_cast<BinaryOperator>(StoreE);
  if (!BO)
    return;

  ProgramStateRef State = C.getState();

  // Case A: a data_pointer field is overwritten. The descriptor no longer
  // retains an unchecked data pointer.
  if (BO->getOpcode() == BO_Assign) {
    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    if (const auto *ME = dyn_cast<MemberExpr>(LHS)) {
      if (knighter::declIsRole(ME->getMemberDecl(), "data_pointer")) {
        if (const MemRegion *Base = getBaseRegionFromMemberBase(ME, C))
          State = State->remove<RetainedUncheckedMap>(Base);
      }
    }
  }

  if (BO->getOpcode() == BO_Assign) {
    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

    // Case B: descriptor is copied, e.g. `*dst = *src`. If the source
    // descriptor has a validated length but an unchecked data pointer,
    // mark the destination descriptor as retaining an unchecked pointer.
    const MemRegion *SrcReg = nullptr;
    if (const auto *UO = dyn_cast<UnaryOperator>(RHS)) {
      if (UO->getOpcode() == UO_Deref) {
        SrcReg = getMemRegionFromExpr(UO->getSubExpr(), C);
      }
    }

    if (SrcReg) {
      SrcReg = SrcReg->getBaseRegion();
      const bool *LenValid = State->get<LengthValidatedMap>(SrcReg);
      const bool *DataChecked = State->get<DataCheckedMap>(SrcReg);

      if (LenValid && *LenValid && (!DataChecked || !*DataChecked)) {
        const MemRegion *DstReg = nullptr;
        if (const auto *UO = dyn_cast<UnaryOperator>(LHS)) {
          if (UO->getOpcode() == UO_Deref) {
            DstReg = getMemRegionFromExpr(UO->getSubExpr(), C);
          }
        }

        if (DstReg) {
          DstReg = DstReg->getBaseRegion();
          State = State->set<RetainedUncheckedMap>(DstReg, true);
        }
      }
    }

    // Case C: a descriptor with an unchecked data pointer is stored through
    // a retained pointer, e.g. `*blobp = nblob`.
    const MemRegion *RhsReg = getMemRegionFromExpr(BO->getRHS(), C);
    if (RhsReg) {
      RhsReg = RhsReg->getBaseRegion();
      const bool *Retained = State->get<RetainedUncheckedMap>(RhsReg);

      if (Retained && *Retained) {
        if (const auto *UO = dyn_cast<UnaryOperator>(LHS)) {
          if (UO->getOpcode() == UO_Deref) {
            const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
            if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
              if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
                if (knighter::declIsRole(VD, "retained_pointer")) {
                  reportRetainedDescriptor(StoreE, C);
                }
              }
            }
          }
        }
      }
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::reportMissingNullCheck(const Stmt *S,
                                              CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing NULL check for data_pointer", N);
  if (S)
    Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::reportRetainedDescriptor(const Stmt *S,
                                                CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Retaining descriptor with unchecked data_pointer", N);
  if (S)
    Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects descriptors whose data pointer is used without a NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "data_pointer": {"names": ["data"], "description": "pointer field holding the data buffer of a descriptor"},
  "length_of": {"names": ["len"], "description": "length field paired with data_pointer"},
  "allocator": {"names": ["curlx_malloc"], "description": "memory allocation function"},
  "deallocator": {"names": ["curlx_safefree"], "description": "memory deallocation function"},
  "buffer_copy": {"names": ["memcpy"], "description": "function that copies between buffers"},
  "copy_flag": {"names": ["CURL_BLOB_COPY"], "description": "flag indicating the data should be copied rather than referenced"},
  "error_setter": {"names": ["CURLE_BAD_FUNCTION_ARGUMENT", "CURLE_OUT_OF_MEMORY"], "description": "return value/macro used to signal an argument error or out-of-memory"},
  "retained_pointer": {"names": ["blobp"], "description": "output parameter through which the descriptor is retained/returned"}
}
*/
