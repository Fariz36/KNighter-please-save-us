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
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class LoopCounterCollector : public RecursiveASTVisitor<LoopCounterCollector> {
public:
  llvm::SmallPtrSet<const VarDecl *, 8> LoopCounters;

  bool VisitForStmt(ForStmt *S) {
    if (const Expr *Inc = S->getInc()) {
      collectDeclRefs(Inc);
    }
    return true;
  }

private:
  void collectDeclRefs(const Stmt *S) {
    if (!S)
      return;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        LoopCounters.insert(VD);
      }
    }

    for (const Stmt *Child : S->children()) {
      collectDeclRefs(Child);
    }
  }
};

static void collectLoopCounters(const FunctionDecl *FD,
                                llvm::SmallPtrSetImpl<const VarDecl *> &LoopCounters) {
  if (!FD)
    return;

  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  LoopCounterCollector Collector;
  Collector.TraverseStmt(Body);

  for (const VarDecl *VD : Collector.LoopCounters) {
    LoopCounters.insert(VD);
  }
}

static bool isAssertCondition(const Stmt *Condition, CheckerContext &C) {
  if (!Condition)
    return false;

  const SourceManager &SM = C.getSourceManager();

  auto checkLoc = [&](SourceLocation Loc) -> bool {
    if (!Loc.isValid())
      return false;

    if (SM.isMacroBodyExpansion(Loc)) {
      StringRef Name = Lexer::getImmediateMacroName(Loc, SM, C.getLangOpts());
      if (Name == "assert")
        return true;
    }

    if (SM.isMacroArgExpansion(Loc)) {
      StringRef Name = Lexer::getImmediateMacroName(Loc, SM, C.getLangOpts());
      if (Name == "assert")
        return true;
    }

    return false;
  };

  if (checkLoc(Condition->getBeginLoc()))
    return true;
  if (checkLoc(Condition->getEndLoc()))
    return true;

  return false;
}

static const Expr *stripParensAndNot(const Expr *E) {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();

  while (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      E = UO->getSubExpr()->IgnoreParenImpCasts();
      continue;
    }
    break;
  }

  return E;
}

static bool containsArithmeticOp(const Expr *E) {
  if (!E)
    return false;

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_Add || Op == BO_Sub || Op == BO_Mul)
      return true;
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *ChildE = dyn_cast<Expr>(Child)) {
      if (containsArithmeticOp(ChildE))
        return true;
    }
  }

  return false;
}

static bool containsLoopCounterRef(
    const Expr *E,
    const llvm::SmallPtrSetImpl<const VarDecl *> &LoopCounters) {
  if (!E)
    return false;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (LoopCounters.count(VD))
        return true;
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *ChildE = dyn_cast<Expr>(Child)) {
      if (containsLoopCounterRef(ChildE, LoopCounters))
        return true;
    }
  }

  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow in assert", "Integer Overflow")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  if (!isAssertCondition(Condition, C))
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const Expr *E = stripParensAndNot(CondE);
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_LT && Op != BO_GT && Op != BO_LE && Op != BO_GE)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  ASTContext &ACtx = C.getASTContext();
  QualType LHSty = LHS->getType();
  QualType RHSty = RHS->getType();

  if (!LHSty->isIntegerType() || !RHSty->isIntegerType())
    return;

  unsigned LHSBits = ACtx.getTypeSize(LHSty);
  unsigned RHSBits = ACtx.getTypeSize(RHSty);

  const Expr *NarrowExpr = nullptr;
  if (LHSBits == 32 && RHSBits == 64) {
    NarrowExpr = LHS;
  } else if (LHSBits == 64 && RHSBits == 32) {
    NarrowExpr = RHS;
  } else {
    return;
  }

  if (!containsArithmeticOp(NarrowExpr))
    return;

  const FunctionDecl *FD =
      dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!FD)
    return;

  llvm::SmallPtrSet<const VarDecl *, 16> LoopCounters;
  collectLoopCounters(FD, LoopCounters);
  if (LoopCounters.empty())
    return;

  if (!containsLoopCounterRef(NarrowExpr, LoopCounters))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential integer overflow: 32-bit loop counter used in arithmetic "
      "compared to 64-bit size in assert().",
      N);
  report->addRange(Condition->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in assert() when 32-bit loop counters are used "
      "in arithmetic compared to a 64-bit size",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
