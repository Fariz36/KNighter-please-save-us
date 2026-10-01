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

#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Set of pointer-field MemRegions that have already been null-checked.
REGISTER_SET_WITH_PROGRAMSTATE(ValidatedPtrFields, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::PreCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing validation of pointer field",
                       "Null pointer dereference")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportBug(const Expr *Arg, CheckerContext &C) const;
};

} // end anonymous namespace

// Returns true if the current function being analyzed is Curl_setblobopt.
static bool isCurlSetblobopt(CheckerContext &C) {
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  return FD && FD->getName() == "Curl_setblobopt";
}

// Returns true if E is exactly the field access "blob->data" where blob is a
// parameter of the current function (Curl_setblobopt).
static bool isBlobDataField(const Expr *E) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  const MemberExpr *ME = dyn_cast<MemberExpr>(E);
  if (!ME)
    return false;

  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD || VD->getName() != "data")
    return false;

  const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base);
  if (!DRE)
    return false;

  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD || PVD->getName() != "blob")
    return false;

  // Optionally verify the parameter type is a pointer to struct curl_blob.
  QualType QT = PVD->getType();
  if (const PointerType *PT = QT->getAs<PointerType>()) {
    QualType Pointee = PT->getPointeeType();
    if (const RecordType *RT = Pointee->getAs<RecordType>()) {
      if (const RecordDecl *RD = RT->getDecl()) {
        if (RD->getName() == "curl_blob")
          return true;
      }
    }
  }

  // Fall back to name matching if the type is not readily available.
  return true;
}

// Returns the MemRegion of the field "blob->data", or nullptr if E is not that
// field.  We evaluate the lvalue MemberExpr (after stripping implicit casts)
// so that we get the region of the field itself, not the pointer value stored
// in it.
static const MemRegion *getBlobDataFieldRegion(const Expr *E,
                                               CheckerContext &C) {
  if (!E)
    return nullptr;

  const Expr *Stripped = E->IgnoreParenImpCasts();
  if (!isBlobDataField(Stripped))
    return nullptr;

  return getMemRegionFromExpr(Stripped, C);
}

// Returns true if E is a null constant (NULL, 0, or a null pointer constant).
static bool isNullConstant(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  if (isa<GNUNullExpr>(E))
    return true;

  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue() == 0;

  return E->isNullPointerConstant(C.getASTContext(),
                                  Expr::NPC_ValueDependentIsNull);
}

// Mark blob->data as validated in the current program state.
static ProgramStateRef markValidated(ProgramStateRef State, const Expr *E,
                                     CheckerContext &C) {
  const MemRegion *MR = getBlobDataFieldRegion(E, C);
  if (!MR)
    return State;

  return State->add<ValidatedPtrFields>(MR);
}

// Recursively inspect a condition for null-checks of blob->data.
static ProgramStateRef validateCondition(ProgramStateRef State, const Expr *E,
                                         CheckerContext &C) {
  if (!E)
    return State;

  // Direct truthiness: if (blob->data)
  State = markValidated(State, E, C);

  const Expr *E2 = E->IgnoreParenImpCasts();
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E2)) {
    if (UO->getOpcode() == UO_LNot) {
      // if (!blob->data)
      State = markValidated(State, UO->getSubExpr(), C);
    }
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E2)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_LAnd || Op == BO_LOr) {
      State = validateCondition(State, BO->getLHS(), C);
      State = validateCondition(State, BO->getRHS(), C);
    } else if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();
      if (isBlobDataField(LHS) && isNullConstant(RHS, C)) {
        State = markValidated(State, LHS, C);
      } else if (isBlobDataField(RHS) && isNullConstant(LHS, C)) {
        State = markValidated(State, RHS, C);
      }
    }
  }
  return State;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!isCurlSetblobopt(C))
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();
  ProgramStateRef NewState = validateCondition(State, CondE, C);
  if (NewState != State)
    C.addTransition(NewState);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isCurlSetblobopt(C))
    return;

  llvm::SmallVector<unsigned, 4> DerefParams;
  functionKnownToDeref(Call, DerefParams);

  // memcpy: the second argument (index 1) is the source and is read from.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (OriginExpr && ExprHasName(OriginExpr, "memcpy", C)) {
    bool Found = false;
    for (unsigned Idx : DerefParams) {
      if (Idx == 1) {
        Found = true;
        break;
      }
    }
    if (!Found)
      DerefParams.push_back(1);
  }

  if (DerefParams.empty())
    return;

  ProgramStateRef State = C.getState();
  for (unsigned Idx : DerefParams) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *Arg = Call.getArgExpr(Idx);
    if (!Arg || !isBlobDataField(Arg))
      continue;

    const MemRegion *MR = getBlobDataFieldRegion(Arg, C);
    if (!MR)
      continue;

    if (!State->contains<ValidatedPtrFields>(MR)) {
      reportBug(Arg, C);
      return; // report only once per call
    }
  }
}

void SAGenTestChecker::reportBug(const Expr *Arg, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "blob->data is not validated for NULL before being dereferenced", N);
  Report->addRange(Arg->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing validation of blob->data before use in Curl_setblobopt",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
