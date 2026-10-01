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
#include "clang/AST/Stmt.h"
#include "llvm/ADT/SmallPtrSet.h"

#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Returns true if the variable name contains one of the length/offset-like
// keywords we care about (case-insensitive).
static bool containsKeyword(StringRef Name) {
  if (Name.empty())
    return false;

  std::string LowerName = Name.lower();
  return LowerName.find("len") != std::string::npos ||
         LowerName.find("off") != std::string::npos ||
         LowerName.find("size") != std::string::npos ||
         LowerName.find("offset") != std::string::npos ||
         LowerName.find("count") != std::string::npos;
}

// Returns true if the expression contains a reference to a narrow integer
// variable whose name looks like a length/offset/size/count.
static bool containsNarrowIntVar(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return false;

    QualType QT = VD->getType();
    ASTContext &AC = C.getASTContext();

    if (!QT->isIntegerType())
      return false;

    // Exclude boolean.
    if (QT->isBooleanType())
      return false;

    unsigned VarBits = AC.getTypeSize(QT);
    unsigned SizeTBits = AC.getTypeSize(AC.getSizeType());
    if (VarBits >= SizeTBits)
      return false;

    if (!containsKeyword(VD->getName()))
      return false;

    return true;
  }

  // Recursively check children.
  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child)) {
      if (containsNarrowIntVar(ChildE, C))
        return true;
    }
  }

  return false;
}

// Returns true if the expression E contains an addition whose operand(s)
// contain a narrow integer variable of interest.
static bool containsNarrowIntInAdd(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Add) {
      if (containsNarrowIntVar(BO->getLHS(), C) ||
          containsNarrowIntVar(BO->getRHS(), C))
        return true;
      return false;
    }

    // Look for a nested addition under other binary operators.
    return containsNarrowIntInAdd(BO->getLHS(), C) ||
           containsNarrowIntInAdd(BO->getRHS(), C);
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    return containsNarrowIntInAdd(UO->getSubExpr(), C);
  }

  if (const auto *CE = dyn_cast<CastExpr>(E)) {
    return containsNarrowIntInAdd(CE->getSubExpr(), C);
  }

  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;
  mutable llvm::SmallPtrSet<const Stmt *, 16> ReportedConds;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Narrow integer overflow in size check",
                       "Integer Overflow")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenImpCasts();

  const auto *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GT && Op != BO_GE && Op != BO_LT && Op != BO_LE)
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();

  if (!containsNarrowIntInAdd(LHS, C) && !containsNarrowIntInAdd(RHS, C))
    return;

  // Avoid duplicate reports for the same condition on different paths.
  if (ReportedConds.count(Condition))
    return;
  ReportedConds.insert(Condition);

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "narrow integer in size-check arithmetic may overflow", N);
  Report->addRange(Condition->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects narrow integer types used in size-check arithmetic that may overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
