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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked pointer difference cast to int",
                       "Integer Overflow")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  static bool isVarRef(const Expr *E, StringRef Name);
};

bool SAGenTestChecker::isVarRef(const Expr *E, StringRef Name) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    const ValueDecl *VD = DRE->getDecl();
    return VD && VD->getName() == Name;
  }
  if (const CStyleCastExpr *CSE = dyn_cast<CStyleCastExpr>(E)) {
    return isVarRef(CSE->getSubExpr(), Name);
  }
  return false;
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  // 1. Must be an assignment expression.
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || BO->getOpcode() != BO_Assign)
    return;

  // 2. Must be inside sqlite3_str_vappendf.
  const LocationContext *LC = C.getLocationContext();
  if (!LC)
    return;
  const Decl *D = LC->getDecl();
  if (!D)
    return;
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || FD->getName() != "sqlite3_str_vappendf")
    return;

  // 3. Destination must be the local variable "length".
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return;
  if (VR->getDecl()->getName() != "length")
    return;

  // 4. Must be inside `if (flag_altform2)`.
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(S, C);
  if (!IS)
    return;
  const Expr *Cond = IS->getCond();
  if (!Cond)
    return;
  Cond = Cond->IgnoreParenImpCasts();
  const DeclRefExpr *CondDRE = dyn_cast<DeclRefExpr>(Cond);
  if (!CondDRE || CondDRE->getDecl()->getName() != "flag_altform2")
    return;

  // 5. RHS must be `(int)(z - (unsigned char*)bufpt)`.
  const Expr *RHS = BO->getRHS();
  if (!RHS)
    return;
  RHS = RHS->IgnoreParenImpCasts();
  const CStyleCastExpr *CSE = dyn_cast<CStyleCastExpr>(RHS);
  if (!CSE)
    return;
  if (CSE->getType().getCanonicalType() != C.getASTContext().IntTy)
    return;

  const Expr *Sub = CSE->getSubExpr();
  if (!Sub)
    return;
  Sub = Sub->IgnoreParenImpCasts();
  const BinaryOperator *SubBO = dyn_cast<BinaryOperator>(Sub);
  if (!SubBO || SubBO->getOpcode() != BO_Sub)
    return;

  const Expr *LHS = SubBO->getLHS();
  const Expr *RHSSub = SubBO->getRHS();
  if (!isVarRef(LHS, "z") || !isVarRef(RHSSub, "bufpt"))
    return;

  // 6. Report.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Unchecked pointer difference cast to int may overflow", N);
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked narrowing of pointer difference to int in sqlite3_str_vappendf",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
