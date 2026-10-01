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

#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "clang/AST/ASTContext.h"
#include "llvm/ADT/APInt.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map to track variables that hold the result of !!memcmp(...)
REGISTER_MAP_WITH_PROGRAMSTATE(InvertedMemcmpMap, const MemRegion *, bool)

namespace {
class SAGenTestChecker : public Checker<check::Bind, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Inverted memcmp result",
                       "Logic Error")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportInvertedMemcmp(const Stmt *S, CheckerContext &C) const;
};
} // end anonymous namespace

static bool isMemcmpCall(const CallExpr *CE) {
  if (!CE)
    return false;
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return false;
  return FD->getNameAsString() == "memcmp";
}

static bool containsDoubleNegMemcmp(const Expr *E) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const auto *UO2 = dyn_cast<UnaryOperator>(Sub)) {
        if (UO2->getOpcode() == UO_LNot) {
          const Expr *Sub2 = UO2->getSubExpr()->IgnoreParenImpCasts();
          if (const auto *CE = dyn_cast<CallExpr>(Sub2)) {
            if (isMemcmpCall(CE))
              return true;
          }
        }
      }
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child)) {
      if (containsDoubleNegMemcmp(ChildE))
        return true;
    }
  }
  return false;
}

static bool getPositiveMatchVar(const Expr *Cond, const DeclRefExpr *&DRE) {
  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *D = dyn_cast<DeclRefExpr>(Cond)) {
    DRE = D;
    return true;
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op != BO_EQ && Op != BO_NE)
      return false;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

    const DeclRefExpr *Var = nullptr;
    const IntegerLiteral *IL = nullptr;

    if ((Var = dyn_cast<DeclRefExpr>(LHS)) &&
        (IL = dyn_cast<IntegerLiteral>(RHS))) {
      // fall through
    } else if ((Var = dyn_cast<DeclRefExpr>(RHS)) &&
               (IL = dyn_cast<IntegerLiteral>(LHS))) {
      // fall through
    } else {
      return false;
    }

    llvm::APInt Val = IL->getValue();
    if (Op == BO_EQ && Val == 1) {
      DRE = Var;
      return true;
    }
    if (Op == BO_NE && Val == 0) {
      DRE = Var;
      return true;
    }
  }

  return false;
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  const auto *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || BO->getOpcode() != BO_Assign)
    return;

  const Expr *RHS = BO->getRHS();
  if (!RHS)
    return;

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  if (containsDoubleNegMemcmp(RHS)) {
    State = State->set<InvertedMemcmpMap>(MR, true);
  } else {
    State = State->remove<InvertedMemcmpMap>(MR);
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  const DeclRefExpr *DRE = nullptr;
  if (!getPositiveMatchVar(Cond, DRE))
    return;

  const MemRegion *MR = getMemRegionFromExpr(DRE, C);
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *IsInverted = State->get<InvertedMemcmpMap>(MR);
  if (IsInverted && *IsInverted) {
    reportInvertedMemcmp(Condition, C);
  }
}

void SAGenTestChecker::reportInvertedMemcmp(const Stmt *S,
                                            CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Inverted memcmp result: !!memcmp() is true when buffers differ; use "
      "memcmp() == 0 for equality.",
      N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects inverted memcmp result used as a positive match test",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
