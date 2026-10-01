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
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool getDeclRefName(const Expr *E, StringRef &Name) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    const ValueDecl *VD = DRE->getDecl();
    if (VD) {
      Name = VD->getName();
      return !Name.empty();
    }
  }
  return false;
}

static bool isDeclRefToName(const Expr *E, StringRef Name) {
  StringRef Found;
  return getDeclRefName(E, Found) && Found == Name;
}

static bool getArraySubscriptBaseName(const ArraySubscriptExpr *ASE,
                                      StringRef &BaseName) {
  if (!ASE)
    return false;
  return getDeclRefName(ASE->getBase(), BaseName);
}

static bool isArraySubscriptWithIndex(const ArraySubscriptExpr *ASE,
                                      StringRef BaseName,
                                      unsigned Index,
                                      CheckerContext &C) {
  if (!ASE)
    return false;

  StringRef Base;
  if (!getArraySubscriptBaseName(ASE, Base) || Base != BaseName)
    return false;

  llvm::APSInt Eval;
  if (!EvaluateExprToInt(Eval, ASE->getIdx(), C))
    return false;

  if (Eval.isSigned() && Eval.isNegative())
    return false;

  return Eval.getLimitedValue() == Index;
}

static void collectArraySubscripts(
    const Stmt *S,
    llvm::SmallVectorImpl<const ArraySubscriptExpr *> &Out) {
  if (!S)
    return;

  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(S))
    Out.push_back(ASE);

  for (const Stmt *Child : S->children())
    collectArraySubscripts(Child, Out);
}

static bool findSepNameInCondition(const Stmt *S,
                                   StringRef PtrName,
                                   CheckerContext &C,
                                   StringRef &SepName) {
  if (!S)
    return false;

  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();

      const auto *LHSASE =
          dyn_cast<ArraySubscriptExpr>(LHS->IgnoreParenImpCasts());
      const auto *RHSASE =
          dyn_cast<ArraySubscriptExpr>(RHS->IgnoreParenImpCasts());

      if (LHSASE &&
          (isArraySubscriptWithIndex(LHSASE, PtrName, 1, C) ||
           isArraySubscriptWithIndex(LHSASE, PtrName, 2, C))) {
        if (getDeclRefName(RHS, SepName))
          return true;
      }

      if (RHSASE &&
          (isArraySubscriptWithIndex(RHSASE, PtrName, 1, C) ||
           isArraySubscriptWithIndex(RHSASE, PtrName, 2, C))) {
        if (getDeclRefName(LHS, SepName))
          return true;
      }
    }
  }

  for (const Stmt *Child : S->children())
    if (findSepNameInCondition(Child, PtrName, C, SepName))
      return true;

  return false;
}

static bool conditionHasPattern(const Stmt *Condition,
                                CheckerContext &C,
                                StringRef &PtrName,
                                StringRef &SepName) {
  llvm::SmallVector<const ArraySubscriptExpr *, 16> Subscripts;
  collectArraySubscripts(Condition, Subscripts);

  for (const auto *ASE : Subscripts) {
    StringRef Base;
    if (!getArraySubscriptBaseName(ASE, Base) || Base.empty())
      continue;

    bool Has1 = false;
    bool Has2 = false;
    bool Has3 = false;

    for (const auto *Other : Subscripts) {
      if (isArraySubscriptWithIndex(Other, Base, 1, C))
        Has1 = true;
      if (isArraySubscriptWithIndex(Other, Base, 2, C))
        Has2 = true;
      if (isArraySubscriptWithIndex(Other, Base, 3, C))
        Has3 = true;
    }

    if (Has1 && Has2 && Has3) {
      StringRef Sep;
      if (findSepNameInCondition(Condition, Base, C, Sep)) {
        PtrName = Base;
        SepName = Sep;
        return true;
      }
    }
  }

  return false;
}

static bool isZeroConstant(const Expr *E, CheckerContext &C) {
  llvm::APSInt Val;
  if (!EvaluateExprToInt(Val, E, C))
    return false;
  return Val.getLimitedValue() == 0;
}

static bool hasNonNullGuard(const Stmt *S,
                            StringRef SepName,
                            CheckerContext &C) {
  if (!S)
    return false;

  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_LAnd) {
      if (isDeclRefToName(BO->getLHS(), SepName) ||
          isDeclRefToName(BO->getRHS(), SepName))
        return true;
    }

    if (BO->getOpcode() == BO_NE) {
      if (isDeclRefToName(BO->getLHS(), SepName) &&
          isZeroConstant(BO->getRHS(), C))
        return true;
      if (isDeclRefToName(BO->getRHS(), SepName) &&
          isZeroConstant(BO->getLHS(), C))
        return true;
    }
  }

  for (const Stmt *Child : S->children())
    if (hasNonNullGuard(Child, SepName, C))
      return true;

  return false;
}

static bool isPtrIncrement(const Stmt *S,
                           StringRef PtrName,
                           CheckerContext &C) {
  if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc) {
      if (isDeclRefToName(UO->getSubExpr(), PtrName))
        return true;
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_AddAssign) {
      if (isDeclRefToName(BO->getLHS(), PtrName)) {
        llvm::APSInt Val;
        if (EvaluateExprToInt(Val, BO->getRHS(), C) &&
            Val.getLimitedValue() == 1)
          return true;
      }
    }
  }

  return false;
}

static bool isPtr0Subscript(const Expr *E,
                            StringRef PtrName,
                            CheckerContext &C) {
  if (!E)
    return false;

  const Expr *IE = E->IgnoreParenImpCasts();
  const auto *ASE = dyn_cast<ArraySubscriptExpr>(IE);
  return ASE && isArraySubscriptWithIndex(ASE, PtrName, 0, C);
}

static bool isSepAssignStmt(const Stmt *S,
                            StringRef PtrName,
                            StringRef SepName,
                            CheckerContext &C) {
  if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      const auto *VD = dyn_cast<VarDecl>(D);
      if (!VD || VD->getName() != SepName)
        continue;

      if (const Expr *Init = VD->getInit()) {
        if (isPtr0Subscript(Init, PtrName, C))
          return true;
      }
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      if (isDeclRefToName(BO->getLHS(), SepName)) {
        if (isPtr0Subscript(BO->getRHS(), PtrName, C))
          return true;
      }
    }
  }

  return false;
}

static bool findIncrementAndSepAssign(const CompoundStmt *CS,
                                      const Stmt *Before,
                                      StringRef PtrName,
                                      StringRef SepName,
                                      CheckerContext &C) {
  if (!CS || !Before)
    return false;

  bool FoundIncrement = false;
  bool FoundAssign = false;

  for (const Stmt *S : CS->body()) {
    if (S == Before)
      break;

    if (!FoundIncrement && isPtrIncrement(S, PtrName, C))
      FoundIncrement = true;

    if (!FoundAssign && isSepAssignStmt(S, PtrName, SepName, C))
      FoundAssign = true;
  }

  return FoundIncrement && FoundAssign;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read", "Memory safety")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportBug(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  StringRef PtrName;
  StringRef SepName;

  if (!conditionHasPattern(Condition, C, PtrName, SepName))
    return;

  if (hasNonNullGuard(Condition, SepName, C))
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
  if (!CS)
    return;

  if (!findIncrementAndSepAssign(CS, IS, PtrName, SepName, C))
    return;

  reportBug(Condition, C);
}

void SAGenTestChecker::reportBug(const Stmt *Condition,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential out-of-bounds read: missing non-NUL separator check before "
      "fixed-offset access",
      N);

  report->addRange(Condition->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects out-of-bounds reads after delimiter search without a non-NUL "
      "separator guard",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
