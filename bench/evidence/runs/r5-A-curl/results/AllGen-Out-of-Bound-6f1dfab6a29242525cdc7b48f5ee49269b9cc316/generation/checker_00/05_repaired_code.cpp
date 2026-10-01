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

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/APSInt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Map a delimiter variable (e.g. `sep`) to the string pointer variable
// (e.g. `ptr`) from which it was loaded at index 0.
REGISTER_MAP_WITH_PROGRAMSTATE(DelimMap, const VarDecl *, const VarDecl *)

namespace {

static const VarDecl *getVarDeclFromExpr(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    return dyn_cast<VarDecl>(DRE->getDecl());
  return nullptr;
}

static const VarDecl *getBaseVarFromASE(const ArraySubscriptExpr *ASE) {
  if (!ASE)
    return nullptr;
  return getVarDeclFromExpr(ASE->getBase());
}

static bool getConstantIndex(int64_t &Val, const Expr *Idx, CheckerContext &C) {
  if (!Idx)
    return false;
  llvm::APSInt EvalRes;
  if (EvaluateExprToInt(EvalRes, Idx, C)) {
    Val = EvalRes.getSExtValue();
    return true;
  }
  return false;
}

class ConditionVisitor : public RecursiveASTVisitor<ConditionVisitor> {
public:
  CheckerContext &C;
  ProgramStateRef State;
  llvm::SmallPtrSet<const DeclRefExpr *, 16> ComparisonOperandDREs;
  llvm::SmallPtrSet<const VarDecl *, 16> CheckedDelimVars;
  llvm::SmallVector<std::pair<const VarDecl *, const VarDecl *>, 8>
      LookaheadComparisons;

  ConditionVisitor(CheckerContext &C, ProgramStateRef State)
      : C(C), State(State) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_EQ)
      return true;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

    const ArraySubscriptExpr *ASE = nullptr;
    const Expr *DelimExpr = nullptr;

    if ((ASE = dyn_cast<ArraySubscriptExpr>(LHS))) {
      DelimExpr = RHS;
    } else if ((ASE = dyn_cast<ArraySubscriptExpr>(RHS))) {
      DelimExpr = LHS;
    } else {
      return true;
    }

    int64_t IdxVal;
    if (!getConstantIndex(IdxVal, ASE->getIdx(), C) || IdxVal <= 0)
      return true;

    const VarDecl *PtrVar = getBaseVarFromASE(ASE);
    const VarDecl *DelimVar = getVarDeclFromExpr(DelimExpr);
    if (!PtrVar || !DelimVar)
      return true;

    LookaheadComparisons.push_back(std::make_pair(DelimVar, PtrVar));

    // Mark the delimiter DRE as a comparison operand so it is not mistakenly
    // considered a NUL check.
    if (const auto *DRE = dyn_cast<DeclRefExpr>(DelimExpr->IgnoreParenImpCasts()))
      ComparisonOperandDREs.insert(DRE);

    return true;
  }

  bool VisitDeclRefExpr(DeclRefExpr *DRE) {
    if (ComparisonOperandDREs.count(DRE))
      return true;

    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      CheckedDelimVars.insert(VD);

    return true;
  }
};

class SAGenTestChecker
    : public Checker<check::Bind, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NUL Check", "Out-of-Bounds Read")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S,
                 CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition,
                            CheckerContext &C) const;

private:
  void reportMissingNulCheck(const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR) {
    C.addTransition(State);
    return;
  }
  MR = MR->getBaseRegion();

  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR) {
    C.addTransition(State);
    return;
  }

  const VarDecl *DelimVar = VR->getDecl();
  if (!DelimVar) {
    C.addTransition(State);
    return;
  }

  // Handle reassignment: remove any previous mapping for this variable.
  State = State->remove<DelimMap>(DelimVar);

  const Expr *RHS = nullptr;
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign)
      RHS = BO->getRHS();
  } else if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    if (DelimVar->hasInit())
      RHS = DelimVar->getInit();
  }

  if (!RHS) {
    C.addTransition(State);
    return;
  }

  RHS = RHS->IgnoreParenImpCasts();
  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(RHS)) {
    int64_t IdxVal;
    if (getConstantIndex(IdxVal, ASE->getIdx(), C) && IdxVal == 0) {
      const VarDecl *PtrVar = getBaseVarFromASE(ASE);
      if (PtrVar)
        State = State->set<DelimMap>(DelimVar, PtrVar);
    }
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  ProgramStateRef State = C.getState();
  ConditionVisitor Visitor(C, State);
  Visitor.TraverseStmt(const_cast<Stmt *>(Condition));

  llvm::SmallPtrSet<const VarDecl *, 8> ReportedDelims;

  for (const auto &Pair : Visitor.LookaheadComparisons) {
    const VarDecl *DelimVar = Pair.first;
    const VarDecl *PtrVar = Pair.second;

    if (ReportedDelims.count(DelimVar))
      continue;

    const VarDecl *const *MappedPtr = State->get<DelimMap>(DelimVar);
    if (!MappedPtr || *MappedPtr != PtrVar)
      continue;

    if (Visitor.CheckedDelimVars.count(DelimVar))
      continue;

    reportMissingNulCheck(Condition, C);
    ReportedDelims.insert(DelimVar);
    break; // One report per branch condition is enough.
  }
}

void SAGenTestChecker::reportMissingNulCheck(const Stmt *S,
                                             CheckerContext &C) const {
  if (!BT)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing NUL check before multi-byte lookahead on string", N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NUL check before multi-byte lookahead on strings",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
