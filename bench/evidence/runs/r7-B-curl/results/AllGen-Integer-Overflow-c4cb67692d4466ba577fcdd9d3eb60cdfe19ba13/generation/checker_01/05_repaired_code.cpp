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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;
using namespace llvm;

namespace {

// Helper: check if a type is a narrow integer type (<= 16 bits)
static bool isNarrowIntegerType(QualType QT, ASTContext &AC) {
  if (!QT->isIntegerType())
    return false;
  uint64_t Bits = AC.getTypeSize(QT);
  return Bits > 0 && Bits <= 16;
}

// Helper: check if variable name suggests length/offset/size
static bool isSizeLikeName(StringRef Name) {
  return Name.contains("len") || Name.contains("off") ||
         Name.contains("size") || Name.contains("count");
}

// Helper: recursively check if an expression contains a narrow size-like variable
static bool containsNarrowSizeVar(const Stmt *S, ASTContext &AC) {
  if (!S)
    return false;
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S)) {
    const ValueDecl *VD = DRE->getDecl();
    if (const VarDecl *Var = dyn_cast<VarDecl>(VD)) {
      if (isNarrowIntegerType(Var->getType(), AC) &&
          isSizeLikeName(Var->getName())) {
        return true;
      }
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsNarrowSizeVar(Child, AC))
      return true;
  }
  return false;
}

// Helper: check if expression looks like a size/bound (e.g., member or variable)
static bool isSizeBoundExpr(const Expr *E) {
  E = E->IgnoreParenImpCasts();
  return isa<MemberExpr>(E) || isa<DeclRefExpr>(E);
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Narrow integer used in size check",
                       "Integer overflow")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  Cond = Cond->IgnoreParenImpCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GT && Op != BO_GE && Op != BO_LT && Op != BO_LE)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  auto isAdd = [](const Expr *E) {
    if (const BinaryOperator *B = dyn_cast<BinaryOperator>(E))
      return B->getOpcode() == BO_Add;
    return false;
  };

  const Expr *AddExpr = nullptr;
  const Expr *OtherExpr = nullptr;
  if (isAdd(LHS)) {
    AddExpr = LHS;
    OtherExpr = RHS;
  } else if (isAdd(RHS)) {
    AddExpr = RHS;
    OtherExpr = LHS;
  } else {
    return;
  }

  ASTContext &AC = C.getASTContext();
  if (!containsNarrowSizeVar(AddExpr, AC))
    return;
  if (!isSizeBoundExpr(OtherExpr))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Narrow integer used in size check; possible overflow/truncation", N);
  Report->addRange(Cond->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects narrow integer variables used in size checks that may cause "
      "overflow/truncation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
