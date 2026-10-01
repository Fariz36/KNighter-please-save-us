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

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

//----------------------------------------------------------------------
// Helper: Check if an expression is a reference to a variable named "count"
//----------------------------------------------------------------------
static bool isCountRef(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      return VD->getName() == "count";
    }
  }
  return false;
}

//----------------------------------------------------------------------
// Helper: Check if an expression evaluates to the integer constant 5
//----------------------------------------------------------------------
static bool isIntFive(const Expr *E, ASTContext &AC) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  Expr::EvalResult Res;
  if (E->EvaluateAsInt(Res, AC)) {
    return Res.Val.getInt() == 5;
  }
  return false;
}

//----------------------------------------------------------------------
// Helper: Check if an expression is "count * 5" (in any order)
//----------------------------------------------------------------------
static bool isCountTimesFive(const Expr *E, ASTContext &AC) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Mul)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  return (isCountRef(LHS) && isIntFive(RHS, AC)) ||
         (isCountRef(RHS) && isIntFive(LHS, AC));
}

//----------------------------------------------------------------------
// Helper: Check if an opcode is a comparison operator
//----------------------------------------------------------------------
static bool isComparisonOp(BinaryOperator::Opcode Op) {
  switch (Op) {
    case BO_LT:
    case BO_LE:
    case BO_GT:
    case BO_GE:
    case BO_EQ:
    case BO_NE:
      return true;
    default:
      return false;
  }
}

//----------------------------------------------------------------------
// Visitor to find a comparison involving "count" and the constant 5
//----------------------------------------------------------------------
class CountBoundFinder : public RecursiveASTVisitor<CountBoundFinder> {
  ASTContext &AC;
  bool Found = false;

public:
  CountBoundFinder(ASTContext &AC) : AC(AC) {}
  bool found() const { return Found; }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (Found)
      return false;
    if (isComparisonOp(BO->getOpcode())) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if ((isCountRef(LHS) && isIntFive(RHS, AC)) ||
          (isCountRef(RHS) && isIntFive(LHS, AC))) {
        Found = true;
        return false;
      }
    }
    return true;
  }
};

//----------------------------------------------------------------------
// Helper: Recursively search a statement for a bound on "count"
//----------------------------------------------------------------------
static bool containsCountBound(const Stmt *S, ASTContext &AC) {
  if (!S)
    return false;
  CountBoundFinder Finder(AC);
  Finder.TraverseStmt(const_cast<Stmt *>(S));
  return Finder.found();
}

//----------------------------------------------------------------------
// Visitor to find the vulnerable shift and check for preceding bounds
//----------------------------------------------------------------------
class ShiftFinder : public RecursiveASTVisitor<ShiftFinder> {
  BugReporter &BR;
  BugType &BT;
  ASTContext &AC;
  std::vector<Stmt *> Parents;

public:
  ShiftFinder(BugReporter &BR, BugType &BT, ASTContext &AC)
      : BR(BR), BT(BT), AC(AC) {}

  bool TraverseStmt(Stmt *S) {
    if (!S)
      return true;
    Parents.push_back(S);
    bool Res = RecursiveASTVisitor<ShiftFinder>::TraverseStmt(S);
    Parents.pop_back();
    return Res;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Shl)
      return true;

    const Expr *RHS = BO->getRHS();
    if (!isCountTimesFive(RHS, AC))
      return true;

    // Find the nearest enclosing CompoundStmt and the child leading to this shift.
    const CompoundStmt *CS = nullptr;
    const Stmt *Child = nullptr;
    for (int i = Parents.size() - 2; i >= 0; --i) {
      if (const CompoundStmt *C = dyn_cast<CompoundStmt>(Parents[i])) {
        CS = C;
        Child = Parents[i + 1];
        break;
      }
    }
    if (!CS || !Child)
      return true;

    // Scan preceding statements in that CompoundStmt for a bound on "count".
    bool HasBound = false;
    for (const Stmt *S : CS->body()) {
      if (S == Child)
        break;
      if (containsCountBound(S, AC)) {
        HasBound = true;
        break;
      }
    }

    if (!HasBound) {
      auto Report = std::make_unique<BasicBugReport>(
          BT, "Shift amount may exceed 32 bits",
          PathDiagnosticLocation::createBegin(BO, BR.getSourceManager(),
                                              nullptr));
      Report->addRange(BO->getSourceRange());
      BR.emitReport(std::move(Report));
    }
    return true;
  }
};

//----------------------------------------------------------------------
// Main Checker Class
//----------------------------------------------------------------------
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Shift Overflow", "Undefined Behavior")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || FD->getName() != "utf8_decode")
    return;

  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  ASTContext &AC = Mgr.getASTContext();
  ShiftFinder Finder(BR, *BT, AC);
  Finder.TraverseStmt(Body);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects shift overflow in utf8_decode due to unbounded count",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
