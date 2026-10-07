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

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(CheckedPtrs, SymbolRef)

namespace {

static bool isReturningStmt(const Stmt *S) {
  if (!S)
    return false;
  if (isa<ReturnStmt>(S))
    return true;
  if (const CompoundStmt *CS = dyn_cast<CompoundStmt>(S)) {
    if (CS->body_empty())
      return false;
    return isReturningStmt(CS->body_back());
  }
  return false;
}

static bool isParamPointerToRecord(const ParmVarDecl *PVD) {
  if (!PVD)
    return false;
  QualType QT = PVD->getType();
  if (QT->isPointerType())
    return QT->getPointeeType()->isRecordType();
  if (QT->isReferenceType()) {
    QualType NonRef = QT.getNonReferenceType();
    return NonRef->isRecordType();
  }
  return false;
}

static bool isInputStructField(const Expr *E, CheckerContext &C,
                               bool WantPointer,
                               const ParmVarDecl *&OutParam,
                               const FieldDecl *&OutField) {
  if (!E)
    return false;

  E = E->IgnoreParenCasts();
  const MemberExpr *ME = dyn_cast<MemberExpr>(E);
  if (!ME)
    return false;

  const FieldDecl *Field = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!Field)
    return false;

  const Expr *Base = ME->getBase()->IgnoreParenCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base);
  if (!DRE)
    return false;

  const ParmVarDecl *Param = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!Param)
    return false;

  if (!isParamPointerToRecord(Param))
    return false;

  QualType FT = Field->getType();
  if (WantPointer) {
    if (!FT->isPointerType())
      return false;
  } else {
    if (!FT->isIntegerType())
      return false;
  }

  OutParam = Param;
  OutField = Field;
  return true;
}

static ProgramStateRef markPtrChecked(ProgramStateRef State,
                                      const Expr *PtrExpr,
                                      CheckerContext &C) {
  SVal V = State->getSVal(PtrExpr, C.getLocationContext());
  SymbolRef Sym = V.getAsSymbol();
  if (Sym)
    State = State->add<CheckedPtrs>(Sym);
  return State;
}

static ProgramStateRef collectNonNullChecks(ProgramStateRef State,
                                             const Expr *E,
                                             bool evTrue,
                                             CheckerContext &C) {
  if (!E)
    return State;

  E = E->IgnoreParenCasts();

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot)
      return collectNonNullChecks(State, UO->getSubExpr(), !evTrue, C);
  }

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();

    if (Op == BO_LAnd) {
      if (evTrue) {
        State = collectNonNullChecks(State, BO->getLHS(), true, C);
        State = collectNonNullChecks(State, BO->getRHS(), true, C);
      }
      return State;
    }

    if (Op == BO_LOr) {
      if (!evTrue) {
        State = collectNonNullChecks(State, BO->getLHS(), false, C);
        State = collectNonNullChecks(State, BO->getRHS(), false, C);
      }
      return State;
    }

    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      ASTContext &AC = C.getASTContext();

      bool LNull =
          LHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);
      bool RNull =
          RHS->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull);

      const Expr *Ptr = nullptr;
      if (LNull && !RNull)
        Ptr = RHS;
      else if (RNull && !LNull)
        Ptr = LHS;

      if (Ptr) {
        bool isEq = (Op == BO_EQ);
        bool nonNull = isEq ? !evTrue : evTrue;
        if (nonNull)
          State = markPtrChecked(State, Ptr, C);
      }
      return State;
    }
  }

  if (evTrue && E->getType()->isPointerType())
    State = markPtrChecked(State, E, C);

  return State;
}

class SAGenTestChecker
    : public Checker<check::PreCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked NULL Buffer Copy", "Null Pointer")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "buffer_copy"))
    return;
  if (Call.getNumArgs() < 3)
    return;

  const Expr *SrcExpr = Call.getArgExpr(1);
  const Expr *SizeExpr = Call.getArgExpr(2);
  if (!SrcExpr || !SizeExpr)
    return;

  const ParmVarDecl *SrcParam = nullptr;
  const FieldDecl *SrcField = nullptr;
  if (!isInputStructField(SrcExpr, C, true, SrcParam, SrcField))
    return;

  const ParmVarDecl *SizeParam = nullptr;
  const FieldDecl *SizeField = nullptr;
  if (!isInputStructField(SizeExpr, C, false, SizeParam, SizeField))
    return;

  if (SrcParam != SizeParam)
    return;

  ProgramStateRef State = C.getState();
  SVal SrcVal = State->getSVal(SrcExpr, C.getLocationContext());
  SymbolRef Sym = SrcVal.getAsSymbol();
  if (!Sym)
    return;
  if (State->contains<CheckedPtrs>(Sym))
    return;

  llvm::APSInt SizeVal;
  if (EvaluateExprToInt(SizeVal, SizeExpr, C) && SizeVal == 0)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked NULL pointer from input struct used as buffer_copy source",
      N);
  report->addRange(SrcExpr->getSourceRange());
  C.emitReport(std::move(report));
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *Cond = IS->getCond();
  if (!Cond)
    return;

  bool thenReturns = isReturningStmt(IS->getThen());
  bool elseReturns = isReturningStmt(IS->getElse());
  if (!thenReturns && !elseReturns)
    return;
  if (thenReturns && elseReturns)
    return;

  bool survivingTruth = elseReturns;
  ProgramStateRef State = C.getState();
  State = collectNonNullChecks(State, Cond, survivingTruth, C);
  C.addTransition(State);
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked NULL pointer from input struct used as buffer_copy source",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "buffer_copy": {"names": ["memcpy"], "description": "copies a block of memory from a source pointer to a destination pointer; both must be valid for the given length"},
  "allocator": {"names": ["curlx_malloc"], "description": "allocates memory and returns a pointer to it, or NULL on failure"},
  "deallocator": {"names": ["curlx_safefree"], "description": "frees previously allocated memory; the pointer must not be used afterwards"}
}
*/
