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
#include "clang/AST/Decl.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_TRAIT_WITH_PROGRAMSTATE(BlobDataChecked, bool)
REGISTER_TRAIT_WITH_PROGRAMSTATE(BlobDataReported, bool)

namespace {

class SAGenTestChecker : public Checker<
    check::BeginFunction,
    check::BranchCondition,
    check::PreCall,
    check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL check on blob->data",
                       "Curl API")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  void reportMissingNullCheck(const Stmt *S, CheckerContext &C,
                              StringRef Msg) const;
};

} // end anonymous namespace

static bool isCurlSetblobopt(CheckerContext &C) {
  const Decl *D = C.getLocationContext()->getDecl();
  if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D))
    return FD->getName() == "Curl_setblobopt";
  return false;
}

static bool isBlobParamExpr(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
    if (PVD && PVD->getName() == "blob")
      return true;
  }
  return false;
}

static bool isBlobDataExpr(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenCasts();
  const MemberExpr *ME = dyn_cast<MemberExpr>(E);
  if (!ME)
    return false;
  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD || VD->getName() != "data")
    return false;
  return isBlobParamExpr(ME->getBase());
}

static bool isNullPointerConstant(const Expr *E, ASTContext &Ctx) {
  if (!E)
    return false;
  return E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
}

static bool conditionChecksBlobData(const Expr *E, ASTContext &Ctx) {
  if (!E)
    return false;
  E = E->IgnoreParenCasts();

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      if (isBlobDataExpr(UO->getSubExpr()))
        return true;
    }
  }

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      if ((isBlobDataExpr(LHS) && isNullPointerConstant(RHS, Ctx)) ||
          (isBlobDataExpr(RHS) && isNullPointerConstant(LHS, Ctx)))
        return true;
    }
    if (BO->getOpcode() == BO_LAnd || BO->getOpcode() == BO_LOr) {
      return conditionChecksBlobData(BO->getLHS(), Ctx) ||
             conditionChecksBlobData(BO->getRHS(), Ctx);
    }
  }

  if (const ConditionalOperator *CO = dyn_cast<ConditionalOperator>(E)) {
    return conditionChecksBlobData(CO->getCond(), Ctx) ||
           conditionChecksBlobData(CO->getTrueExpr(), Ctx) ||
           conditionChecksBlobData(CO->getFalseExpr(), Ctx);
  }

  if (isBlobDataExpr(E))
    return true;

  return false;
}

static bool isStructCopyFromBlob(const Stmt *S, CheckerContext &C) {
  if (!S)
    return false;
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
  if (!BO) {
    BO = findSpecificTypeInParents<BinaryOperator>(S, C);
  }
  if (!BO || BO->getOpcode() != BO_Assign)
    return false;
  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
  const UnaryOperator *UO = dyn_cast<UnaryOperator>(RHS);
  if (!UO || UO->getOpcode() != UO_Deref)
    return false;
  const Expr *Sub = UO->getSubExpr()->IgnoreParenCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub)) {
    const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
    if (PVD && PVD->getName() == "blob")
      return true;
  }
  return false;
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  if (!isCurlSetblobopt(C))
    return;
  ProgramStateRef State = C.getState();
  State = State->set<BlobDataChecked>(false);
  State = State->set<BlobDataReported>(false);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!isCurlSetblobopt(C))
    return;
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;
  if (conditionChecksBlobData(CondE, C.getASTContext())) {
    ProgramStateRef State = C.getState();
    State = State->set<BlobDataChecked>(true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isCurlSetblobopt(C))
    return;

  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "memcpy", C))
    return;

  const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
  if (!CE || CE->getNumArgs() <= 1)
    return;

  const Expr *SrcArg = CE->getArg(1)->IgnoreImplicit();
  if (!isBlobDataExpr(SrcArg))
    return;

  ProgramStateRef State = C.getState();
  bool Checked = State->get<BlobDataChecked>();
  if (Checked)
    return;
  bool Reported = State->get<BlobDataReported>();
  if (Reported)
    return;

  reportMissingNullCheck(OriginExpr, C,
                         "Missing NULL check on blob->data before memcpy");
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  if (!isCurlSetblobopt(C))
    return;
  if (!isStructCopyFromBlob(S, C))
    return;

  ProgramStateRef State = C.getState();
  bool Checked = State->get<BlobDataChecked>();
  if (Checked)
    return;
  bool Reported = State->get<BlobDataReported>();
  if (Reported)
    return;

  reportMissingNullCheck(S, C, "Missing NULL check on blob->data before copy");
}

void SAGenTestChecker::reportMissingNullCheck(const Stmt *S, CheckerContext &C,
                                              StringRef Msg) const {
  ProgramStateRef State = C.getState();
  State = State->set<BlobDataReported>(true);
  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL check on blob->data in Curl_setblobopt",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
