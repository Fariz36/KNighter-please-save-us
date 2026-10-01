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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(TokenTextMap, const MemRegion *, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(CheckedTokenTypes, const MemRegion *)

namespace {
class SAGenTestChecker : public Checker<
    check::PostCall,
    check::PreCall,
    check::BranchCondition
> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked TK_ILLEGAL token",
                       "SQLite API Misuse")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportUncheckedDequote(const CallEvent &Call, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const Expr *CE = Call.getOriginExpr();
  if (!CE)
    return;

  // Track getConstraintToken(&zSql[iOff], &t)
  if (ExprHasName(CE, "getConstraintToken", C)) {
    if (Call.getNumArgs() < 2)
      return;

    SVal Arg0 = Call.getArgSVal(0);
    SVal Arg1 = Call.getArgSVal(1);
    const MemRegion *TextMR = Arg0.getAsRegion();
    const MemRegion *TypeMR = Arg1.getAsRegion();
    if (!TextMR || !TypeMR)
      return;

    TextMR = TextMR->getBaseRegion();
    TypeMR = TypeMR->getBaseRegion();

    State = State->set<TokenTextMap>(TextMR, TypeMR);
    C.addTransition(State);
    return;
  }

  // Propagate token type association through memcpy/memmove.
  if (ExprHasName(CE, "memcpy", C) || ExprHasName(CE, "memmove", C)) {
    if (Call.getNumArgs() < 2)
      return;

    SVal DestVal = Call.getArgSVal(0);
    SVal SrcVal = Call.getArgSVal(1);
    const MemRegion *DestMR = DestVal.getAsRegion();
    const MemRegion *SrcMR = SrcVal.getAsRegion();
    if (!DestMR || !SrcMR)
      return;

    DestMR = DestMR->getBaseRegion();
    SrcMR = SrcMR->getBaseRegion();

    const MemRegion * const *TokenTypePtr = State->get<TokenTextMap>(SrcMR);
    if (!TokenTypePtr)
      return;

    State = State->set<TokenTextMap>(DestMR, *TokenTypePtr);
    C.addTransition(State);
    return;
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;
  if (!ExprHasName(CondE, "TK_ILLEGAL", C))
    return;

  ProgramStateRef State = C.getState();
  CondE = CondE->IgnoreParenCasts();

  // Look for a binary comparison with TK_ILLEGAL on either side.
  const Expr *VarExpr = nullptr;
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE)) {
    if (BO->getOpcode() != BO_EQ && BO->getOpcode() != BO_NE)
      return;

    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
    if (ExprHasName(RHS, "TK_ILLEGAL", C)) {
      VarExpr = LHS;
    } else if (ExprHasName(LHS, "TK_ILLEGAL", C)) {
      VarExpr = RHS;
    }
  }

  if (!VarExpr)
    return;

  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(VarExpr->IgnoreParenCasts());
  if (!DRE)
    return;
  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return;

  const VarRegion *VR = State->getRegion(VD, C.getLocationContext());
  if (!VR)
    return;

  State = State->add<CheckedTokenTypes>(VR);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *CE = Call.getOriginExpr();
  if (!CE || !ExprHasName(CE, "sqlite3Dequote", C))
    return;
  if (Call.getNumArgs() < 1)
    return;

  ProgramStateRef State = C.getState();
  SVal Arg0 = Call.getArgSVal(0);
  const MemRegion *MR = Arg0.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();

  const MemRegion * const *TokenTypePtr = State->get<TokenTextMap>(MR);
  if (!TokenTypePtr)
    return;

  const MemRegion *TokenTypeMR = *TokenTypePtr;
  if (State->contains<CheckedTokenTypes>(TokenTypeMR))
    return;

  reportUncheckedDequote(Call, C);
}

void SAGenTestChecker::reportUncheckedDequote(const CallEvent &Call,
                                              CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "sqlite3Dequote called on token text without checking TK_ILLEGAL",
      N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects sqlite3Dequote calls on token text without checking TK_ILLEGAL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
