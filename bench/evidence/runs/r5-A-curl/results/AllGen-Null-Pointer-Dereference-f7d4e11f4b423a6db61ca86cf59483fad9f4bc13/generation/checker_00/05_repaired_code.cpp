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
#include "clang/AST/Decl.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Casting.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state set to track validated pointer fields.
REGISTER_SET_WITH_PROGRAMSTATE(CheckedFields, const MemRegion *)

namespace {

// Helper: Check if a MemberExpr is exactly blob->data.
static bool isBlobDataMember(const MemberExpr *ME) {
  if (!ME)
    return false;
  if (ME->getMemberDecl()->getName() != "data")
    return false;
  const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base)) {
    if (const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
      return PVD->getName() == "blob";
    }
  }
  return false;
}

// Helper: Find a blob->data MemberExpr inside a statement.
static const MemberExpr *findBlobDataMember(const Stmt *S) {
  if (!S)
    return nullptr;
  if (const MemberExpr *ME = dyn_cast<MemberExpr>(S)) {
    if (isBlobDataMember(ME))
      return ME;
  }
  for (const Stmt *Child : S->children()) {
    if (const MemberExpr *ME = findBlobDataMember(Child))
      return ME;
  }
  return nullptr;
}

class SAGenTestChecker
    : public Checker<check::BranchCondition, check::PreCall,
                     check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL Check on blob->data",
                       "API Misuse")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;

private:
  bool isCurlSetblobopt(CheckerContext &C) const;
  void reportMissingNullCheck(const Stmt *S, CheckerContext &C,
                              StringRef Msg) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isCurlSetblobopt(CheckerContext &C) const {
  const LocationContext *LC = C.getLocationContext();
  if (!LC)
    return false;
  const Decl *D = LC->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return false;
  return FD->getName() == "Curl_setblobopt";
}

void SAGenTestChecker::reportMissingNullCheck(const Stmt *S, CheckerContext &C,
                                              StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  if (S)
    report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!isCurlSetblobopt(C))
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  // Check that the 'then' branch is a return of CURLE_BAD_FUNCTION_ARGUMENT.
  const Stmt *Then = IS->getThen();
  const ReturnStmt *RS = dyn_cast<ReturnStmt>(Then);
  if (!RS) {
    if (const CompoundStmt *CS = dyn_cast<CompoundStmt>(Then)) {
      if (CS->size() == 1)
        RS = dyn_cast<ReturnStmt>(CS->body_front());
    }
  }
  if (!RS)
    return;
  const Expr *RetExpr = RS->getRetValue();
  if (!RetExpr || !ExprHasName(RetExpr, "CURLE_BAD_FUNCTION_ARGUMENT", C))
    return;

  // Look for blob->data in the condition.
  const MemberExpr *ME = findBlobDataMember(Condition);
  if (!ME)
    return;

  const MemRegion *Reg = getMemRegionFromExpr(ME, C);
  if (!Reg)
    return;
  Reg = Reg->getBaseRegion();
  if (!Reg)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<CheckedFields>(Reg);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isCurlSetblobopt(C))
    return;

  const IdentifierInfo *ID = Call.getCalleeIdentifier();
  if (!ID || ID->getName() != "memcpy")
    return;
  if (Call.getNumArgs() < 2)
    return;

  const Expr *SrcArg = Call.getArgExpr(1);
  if (!SrcArg)
    return;

  const MemberExpr *ME = dyn_cast<MemberExpr>(SrcArg->IgnoreParenImpCasts());
  if (!ME || !isBlobDataMember(ME))
    return;

  const MemRegion *Reg = getMemRegionFromExpr(ME, C);
  if (!Reg)
    return;
  Reg = Reg->getBaseRegion();
  if (!Reg)
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<CheckedFields>(Reg))
    return;

  reportMissingNullCheck(Call.getOriginExpr(), C,
                         "Missing NULL check on blob->data before memcpy");
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO,
                                    CheckerContext &C) const {
  if (!isCurlSetblobopt(C))
    return;

  if (BO->getOpcode() != BO_Assign)
    return;

  const Expr *RHS = BO->getRHS();
  if (!RHS)
    return;

  // RHS should be *blob.
  const UnaryOperator *UO = dyn_cast<UnaryOperator>(RHS->IgnoreParenImpCasts());
  if (!UO || UO->getOpcode() != UO_Deref)
    return;

  const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub);
  if (!DRE)
    return;
  const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
  if (!PVD || PVD->getName() != "blob")
    return;

  const MemRegion *Reg = getMemRegionFromExpr(RHS, C);
  if (!Reg)
    return;
  Reg = Reg->getBaseRegion();
  if (!Reg)
    return;

  ProgramStateRef State = C.getState();
  if (State->contains<CheckedFields>(Reg))
    return;

  reportMissingNullCheck(
      BO, C, "Missing NULL check on blob->data before storing in nblob");
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL check on blob->data in Curl_setblobopt",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
