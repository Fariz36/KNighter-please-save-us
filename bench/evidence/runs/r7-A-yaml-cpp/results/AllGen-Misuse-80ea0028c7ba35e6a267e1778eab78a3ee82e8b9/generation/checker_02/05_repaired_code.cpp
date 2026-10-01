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

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Check if the expression is of the form `cnt % 4 == 3` or `cnt == 3`.
// On success, `Name` is filled with the counter variable name (e.g., "cnt").
static bool matchCounterCondition(const Expr *E, std::string &Name) {
  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_EQ)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  auto isLiteral3 = [](const Expr *E) {
    if (const auto *IL = dyn_cast<IntegerLiteral>(E)) {
      return IL->getValue().getZExtValue() == 3;
    }
    return false;
  };

  const Expr *Other = nullptr;
  if (isLiteral3(LHS))
    Other = RHS;
  else if (isLiteral3(RHS))
    Other = LHS;
  else
    return false;

  // Case: cnt == 3
  if (const auto *DRE = dyn_cast<DeclRefExpr>(Other)) {
    Name = DRE->getDecl()->getName().str();
    return true;
  }

  // Case: cnt % 4 == 3
  if (const auto *BO2 = dyn_cast<BinaryOperator>(Other)) {
    if (BO2->getOpcode() == BO_Rem) {
      const Expr *L = BO2->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO2->getRHS()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(L)) {
        if (const auto *IL = dyn_cast<IntegerLiteral>(R)) {
          if (IL->getValue().getZExtValue() == 4) {
            Name = DRE->getDecl()->getName().str();
            return true;
          }
        }
      }
    }
  }

  return false;
}

// Check if the expression is of the form `cnt != 0` or `cnt % 4 != 0`.
static bool matchValidationCondition(const Expr *E, StringRef CounterName) {
  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_NE)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  auto isZero = [](const Expr *E) {
    if (const auto *IL = dyn_cast<IntegerLiteral>(E)) {
      return IL->getValue().getZExtValue() == 0;
    }
    return false;
  };

  const Expr *Other = nullptr;
  if (isZero(LHS))
    Other = RHS;
  else if (isZero(RHS))
    Other = LHS;
  else
    return false;

  // Case: cnt != 0
  if (const auto *DRE = dyn_cast<DeclRefExpr>(Other)) {
    return DRE->getDecl()->getName() == CounterName;
  }

  // Case: cnt % 4 != 0
  if (const auto *BO2 = dyn_cast<BinaryOperator>(Other)) {
    if (BO2->getOpcode() == BO_Rem) {
      const Expr *L = BO2->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO2->getRHS()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(L)) {
        if (DRE->getDecl()->getName() == CounterName) {
          if (const auto *IL = dyn_cast<IntegerLiteral>(R)) {
            return IL->getValue().getZExtValue() == 4;
          }
        }
      }
    }
  }

  return false;
}

// Check if a statement contains a ReturnStmt (recursively).
static bool containsReturn(const Stmt *S) {
  if (!S)
    return false;
  if (isa<ReturnStmt>(S))
    return true;
  for (const Stmt *Child : S->children()) {
    if (containsReturn(Child))
      return true;
  }
  return false;
}

// Visitor to find an IfStmt inside the decoding loop that checks the
// 4-character group boundary condition.
class CounterConditionVisitor
    : public RecursiveASTVisitor<CounterConditionVisitor> {
public:
  std::string CounterName;
  bool Found = false;

  bool VisitIfStmt(IfStmt *IS) {
    if (Found)
      return true;
    if (matchCounterCondition(IS->getCond(), CounterName)) {
      Found = true;
    }
    return true;
  }
};

// Visitor to find an increment of the counter variable inside the loop body.
class IncrementVisitor : public RecursiveASTVisitor<IncrementVisitor> {
  StringRef Name;

public:
  bool Found = false;
  IncrementVisitor(StringRef N) : Name(N) {}

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (Found)
      return true;
    auto Op = UO->getOpcode();
    if (Op == UO_PreInc || Op == UO_PostInc) {
      if (const auto *DRE = dyn_cast<DeclRefExpr>(
              UO->getSubExpr()->IgnoreParenImpCasts())) {
        if (DRE->getDecl()->getName() == Name) {
          Found = true;
          return false;
        }
      }
    }
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Base64 Decoder", "Truncated Input")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  if (FD->getName() != "DecodeBase64")
    return;

  Stmt *Body = FD->getBody();
  if (!Body)
    return;
  CompoundStmt *CS = dyn_cast<CompoundStmt>(Body);
  if (!CS)
    return;

  ForStmt *MainLoop = nullptr;
  std::string CounterName;

  // Find the main Base64 decoding loop.
  for (Stmt *S : CS->body()) {
    ForStmt *FS = dyn_cast<ForStmt>(S);
    if (!FS)
      continue;

    // Look for the 4-character group processing condition.
    CounterConditionVisitor CondVisitor;
    CondVisitor.TraverseStmt(FS->getBody());
    if (!CondVisitor.Found)
      continue;

    // Verify the loop body contains an increment of the counter.
    IncrementVisitor IncVisitor(CondVisitor.CounterName);
    IncVisitor.TraverseStmt(FS->getBody());
    if (!IncVisitor.Found)
      continue;

    MainLoop = FS;
    CounterName = CondVisitor.CounterName;
    break;
  }

  if (!MainLoop)
    return;

  // Check for a final validation statement after the loop in the same
  // compound statement.
  bool FoundValidation = false;
  bool AfterLoop = false;
  for (Stmt *S : CS->body()) {
    if (S == MainLoop) {
      AfterLoop = true;
      continue;
    }
    if (!AfterLoop)
      continue;

    IfStmt *IS = dyn_cast<IfStmt>(S);
    if (!IS)
      continue;

    if (matchValidationCondition(IS->getCond(), CounterName)) {
      if (containsReturn(IS->getThen())) {
        FoundValidation = true;
        break;
      }
    }
  }

  if (!FoundValidation) {
    if (!BT)
      return;
    auto R = std::make_unique<BasicBugReport>(
        *BT,
        "Base64 decoder does not reject truncated input; missing final check "
        "for incomplete 4-character group.",
        PathDiagnosticLocation(MainLoop, BR.getSourceManager(), nullptr));
    R->addRange(MainLoop->getSourceRange());
    BR.emitReport(std::move(R));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing validation in Base64 decoder for truncated input",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
