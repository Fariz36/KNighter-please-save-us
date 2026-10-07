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
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/SmallVector.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(NullCheckedFieldMap, const MemRegion *, bool)

namespace {

static const ParmVarDecl *getParmFromMemberBase(const MemberExpr *ME) {
  if (!ME)
    return nullptr;

  const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(Base);
  if (!DRE)
    return nullptr;

  const auto *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD)
    return nullptr;

  QualType QT = PVD->getType();
  if (!QT->isPointerType())
    return nullptr;

  QualType Pointee = QT->getPointeeType();
  if (!Pointee->isRecordType())
    return nullptr;

  return PVD;
}

static bool isPointerFieldMemberExpr(const MemberExpr *ME) {
  if (!ME)
    return false;
  if (!getParmFromMemberBase(ME))
    return false;
  return ME->getType()->isPointerType();
}

static void collectNullCheckedFields(const Expr *Cond, CheckerContext &C,
                                     SmallVectorImpl<const MemRegion *> &Regions) {
  if (!Cond)
    return;

  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_LOr || BO->getOpcode() == BO_LAnd) {
      collectNullCheckedFields(BO->getLHS(), C, Regions);
      collectNullCheckedFields(BO->getRHS(), C, Regions);
      return;
    }

    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LNull = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RNull = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);

      const Expr *FieldExpr = nullptr;
      if (LNull && !RNull)
        FieldExpr = RHS;
      else if (RNull && !LNull)
        FieldExpr = LHS;

      if (FieldExpr) {
        if (const auto *ME = dyn_cast<MemberExpr>(FieldExpr)) {
          if (isPointerFieldMemberExpr(ME)) {
            SVal BaseVal = C.getSVal(ME->getBase());
            if (const MemRegion *MR = BaseVal.getAsRegion()) {
              Regions.push_back(MR);
            }
          }
        }
      }
      return;
    }
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();

      if (const auto *ME = dyn_cast<MemberExpr>(Sub)) {
        if (isPointerFieldMemberExpr(ME)) {
          SVal BaseVal = C.getSVal(ME->getBase());
          if (const MemRegion *MR = BaseVal.getAsRegion()) {
            Regions.push_back(MR);
          }
        }
      }

      // Handle nested forms such as !(blob->data == NULL).
      collectNullCheckedFields(Sub, C, Regions);
      return;
    }
  }

  if (const auto *ME = dyn_cast<MemberExpr>(Cond)) {
    if (isPointerFieldMemberExpr(ME)) {
      SVal BaseVal = C.getSVal(ME->getBase());
      if (const MemRegion *MR = BaseVal.getAsRegion()) {
        Regions.push_back(MR);
      }
    }
  }
}

class SAGenTestChecker
    : public Checker<check::BranchCondition, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Unchecked NULL input data pointer before buffer copy",
                       "Null Dereference")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  SmallVector<const MemRegion *, 4> Regions;
  collectNullCheckedFields(Cond, C, Regions);
  if (Regions.empty())
    return;

  ProgramStateRef State = C.getState();
  for (const MemRegion *MR : Regions)
    State = State->set<NullCheckedFieldMap>(MR, true);

  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "buffer_copy"))
    return;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  const auto *CE = dyn_cast<CallExpr>(Origin);
  if (!CE)
    return;
  if (CE->getNumArgs() < 3)
    return;

  const Expr *SrcArg = CE->getArg(1)->IgnoreParenImpCasts();
  const Expr *LenArg = CE->getArg(2)->IgnoreParenImpCasts();

  const auto *SrcME = dyn_cast<MemberExpr>(SrcArg);
  if (!SrcME)
    return;
  if (!isPointerFieldMemberExpr(SrcME))
    return;

  const ParmVarDecl *SrcParm = getParmFromMemberBase(SrcME);
  if (!SrcParm)
    return;

  const auto *LenME = dyn_cast<MemberExpr>(LenArg);
  if (!LenME)
    return;
  const ParmVarDecl *LenParm = getParmFromMemberBase(LenME);
  if (LenParm != SrcParm)
    return;

  SVal BaseVal = C.getSVal(SrcME->getBase());
  const MemRegion *MR = BaseVal.getAsRegion();
  if (!MR)
    return;

  const bool *Checked = C.getState()->get<NullCheckedFieldMap>(MR);
  if (Checked && *Checked)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked NULL input data pointer before buffer copy", N);
  Report->addRange(SrcME->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked NULL input data pointers before buffer copy",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "buffer_copy": {"names": ["memcpy"], "description": "copies a buffer from a source pointer to a destination pointer; the source pointer must be valid if the length is nonzero"},
  "allocator": {"names": ["curlx_malloc"], "description": "allocates memory; may return NULL on failure"},
  "deallocator": {"names": ["curlx_safefree"], "description": "frees memory or an object; the pointer must not be used afterwards"},
  "null_on_failure": {"names": ["curlx_malloc"], "description": "returns NULL on failure; its return value must be checked"}
}
*/
