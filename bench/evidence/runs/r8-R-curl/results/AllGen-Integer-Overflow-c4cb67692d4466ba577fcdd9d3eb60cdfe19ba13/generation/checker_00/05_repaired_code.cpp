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
#include "llvm/ADT/SmallVector.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static void collectAddOperands(const Expr *E,
                               llvm::SmallVectorImpl<const Expr *> &Ops) {
  if (!E)
    return;

  E = E->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Add) {
      collectAddOperands(BO->getLHS(), Ops);
      collectAddOperands(BO->getRHS(), Ops);
      return;
    }
  }

  Ops.push_back(E);
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow in Size Check",
                       "Integer Overflow")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &Ctx) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenImpCasts();

  const auto *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return;

  const Expr *AddSide = nullptr;
  switch (BO->getOpcode()) {
  case BO_GT:
  case BO_GE:
    AddSide = BO->getLHS();
    break;
  case BO_LT:
  case BO_LE:
    AddSide = BO->getRHS();
    break;
  default:
    return;
  }

  if (!AddSide)
    return;

  llvm::SmallVector<const Expr *, 8> Operands;
  collectAddOperands(AddSide, Operands);

  const VarDecl *LengthVD = nullptr;
  const VarDecl *OffsetVD = nullptr;

  for (const Expr *Op : Operands) {
    const Expr *E = Op->IgnoreParenImpCasts();
    const auto *DRE = dyn_cast<DeclRefExpr>(E);
    if (!DRE)
      continue;

    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      continue;

    if (knighter::declIsRole(VD, "length_var"))
      LengthVD = VD;
    else if (knighter::declIsRole(VD, "offset_var"))
      OffsetVD = VD;
  }

  if (!LengthVD || !OffsetVD)
    return;

  ASTContext &AC = C.getASTContext();
  QualType LenTy = LengthVD->getType();
  QualType OffTy = OffsetVD->getType();

  if (!LenTy->isIntegerType() || !OffTy->isIntegerType())
    return;

  unsigned SizeWidth = AC.getIntWidth(AC.getSizeType());
  unsigned LenWidth = AC.getIntWidth(LenTy);
  unsigned OffWidth = AC.getIntWidth(OffTy);

  if (SizeWidth == 0 || LenWidth >= SizeWidth || OffWidth >= SizeWidth)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Integer overflow in size check due to narrow integer addition", N);
  Report->addRange(CondE->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in size checks caused by narrow integer addition",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "length_var": {"names": ["len"], "description": "variable holding a length value used in a size check"},
  "offset_var": {"names": ["off"], "description": "variable holding an offset value used in a size check"},
  "size_check": {"names": [], "description": "integer addition used as a bounds check where overflow can bypass the check"}
}
*/
