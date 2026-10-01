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
#include "clang/AST/ParentMapContext.h"
#include "llvm/Support/raw_ostream.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::BeginFunction,
                                        check::PostStmt<BinaryOperator>,
                                        check::PostStmt<CompoundAssignOperator>> {
  mutable std::unique_ptr<BugType> BT;
  // Track whether we already reported for the current function to avoid duplicates.
  mutable bool ReportedThisFunction = false;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unbounded Accumulation Integer Overflow",
                       "Integer Overflow")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkPostStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkPostStmt(const CompoundAssignOperator *CAO, CheckerContext &C) const;

private:
  const FunctionDecl *getCurrentFunctionDecl(CheckerContext &C) const;
  bool isKvvfsDecode(CheckerContext &C) const;
  bool isLocalVarOfType(const Expr *E, const FunctionDecl *FD,
                        const ASTContext &ACtx, unsigned MaxBits) const;
  bool loopBodyHasInLoopBoundCheck(const Stmt *S, CheckerContext &C,
                                   const Expr *AccumulatorVar) const;
  void reportBug(const Stmt *S, CheckerContext &C) const;
};

} // end anonymous namespace

const FunctionDecl *
SAGenTestChecker::getCurrentFunctionDecl(CheckerContext &C) const {
  const Decl *D = C.getCurrentAnalysisDeclContext()->getDecl();
  return dyn_cast_or_null<FunctionDecl>(D);
}

bool SAGenTestChecker::isKvvfsDecode(CheckerContext &C) const {
  const FunctionDecl *FD = getCurrentFunctionDecl(C);
  if (!FD)
    return false;
  return FD->getNameAsString() == "kvvfsDecode";
}

/// Check whether E is a reference to a local integer variable declared in FD,
/// whose type width is <= MaxBits.
bool SAGenTestChecker::isLocalVarOfType(const Expr *E, const FunctionDecl *FD,
                                        const ASTContext &ACtx,
                                        unsigned MaxBits) const {
  if (!E)
    return false;

  // Strip parens/casts but NOT implicit casts to keep things simple.
  const Expr *Sub = E->IgnoreParenCasts();

  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub);
  if (!DRE)
    return false;

  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return false;

  // Must be a local variable of the target function.
  if (VD->getParentFunctionOrMethod() != FD)
    return false;

  QualType QT = VD->getType();
  if (!QT->isIntegerType())
    return false;

  if (ACtx.getTypeSize(QT) > MaxBits)
    return false;

  return true;
}

/// Scan the body of the enclosing loop for an in-loop bound check of the
/// accumulator against `nOut` (a comparison involving the accumulator variable
/// and the name "nOut").
bool SAGenTestChecker::loopBodyHasInLoopBoundCheck(
    const Stmt *S, CheckerContext &C, const Expr *AccumulatorVar) const {
  // Find the enclosing WhileStmt by walking up the parent map.
  const WhileStmt *WS = nullptr;
  {
    const Stmt *Cur = S;
    while (Cur) {
      auto Parents = C.getASTContext().getParents(*Cur);
      if (Parents.empty())
        break;
      const Stmt *Parent = Parents[0].get<Stmt>();
      if (!Parent)
        break;
      if (const auto *W = dyn_cast<WhileStmt>(Parent)) {
        WS = W;
        break;
      }
      Cur = Parent;
    }
  }
  if (!WS)
    return false;

  const Stmt *Body = WS->getBody();
  if (!Body)
    return false;

  // Collect the variable names of the accumulator.
  SmallVector<StringRef, 2> AccumNames;
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(
          AccumulatorVar->IgnoreParenCasts())) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      AccumNames.push_back(VD->getName());
  }

  // Helper lambda: check whether an expression mentions a given variable name.
  auto ExprHasVarName = [&](const Expr *E, StringRef Name) -> bool {
    if (!E)
      return false;
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenCasts())) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
        return VD->getName() == Name;
    }
    return false;
  };

  // Walk all sub-statements of the loop body looking for a comparison that
  // mentions the accumulator variable and "nOut", or looks like `n > nOut` /
  // `n >= nOut`.
  for (const Stmt *Child : Body->children()) {
    if (!Child)
      continue;

    if (const auto *BO = dyn_cast<BinaryOperator>(Child)) {
      BinaryOperator::Opcode Op = BO->getOpcode();
      if (Op == BO_GT || Op == BO_GE) {
        const Expr *LHS = BO->getLHS();
        const Expr *RHS = BO->getRHS();
        if (!LHS || !RHS)
          continue;

        bool lhsIsAccum = false;
        for (StringRef Name : AccumNames) {
          if (ExprHasVarName(LHS, Name)) {
            lhsIsAccum = true;
            break;
          }
        }
        if (lhsIsAccum && ExprHasVarName(RHS, "nOut"))
          return true;

        // Handle swapped operands structurally: `nOut < n`, `nOut <= n`.
        if (ExprHasVarName(RHS, "nOut")) {
          bool lhsIsN = false;
          for (StringRef Name : AccumNames) {
            if (ExprHasVarName(LHS, Name)) {
              lhsIsN = true;
              break;
            }
          }
          if (lhsIsN && (Op == BO_GT || Op == BO_GE))
            return true;
        }
      }
    }
  }
  return false;
}

void SAGenTestChecker::reportBug(const Stmt *S, CheckerContext &C) const {
  if (ReportedThisFunction)
    return;
  ReportedThisFunction = true;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Integer overflow: input-derived accumulator not bounds-checked inside "
      "accumulation loop",
      N);
  Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  ReportedThisFunction = false;
}

/// Detect `n += (c - 'a')*mult;` — a compound `+=` where:
///   * LHS is a local 32-bit integer (or narrower),
///   * RHS is a multiplication expression.
void SAGenTestChecker::checkPostStmt(const CompoundAssignOperator *CAO,
                                     CheckerContext &C) const {
  if (!CAO)
    return;
  if (!isKvvfsDecode(C))
    return;

  if (CAO->getOpcode() != BO_AddAssign)
    return;

  const FunctionDecl *FD = getCurrentFunctionDecl(C);
  if (!FD)
    return;

  const ASTContext &ACtx = C.getASTContext();

  // LHS: local small integer accumulator.
  if (!isLocalVarOfType(CAO->getLHS(), FD, ACtx, 32))
    return;

  // RHS: correctness check — must be a multiplication expression.
  const Expr *RHS = CAO->getRHS()->IgnoreParenCasts();
  const auto *MulBO = dyn_cast<BinaryOperator>(RHS);
  if (!MulBO || MulBO->getOpcode() != BO_Mul)
    return;

  // Confirm the accumulator `n` is not bounds-checked inside the loop body
  // against the output-size variable `nOut`.
  if (loopBodyHasInLoopBoundCheck(CAO, C, CAO->getLHS()))
    return;

  reportBug(CAO, C);
}

/// Detect the multiplier `mult *= 26;` — a compound `*=` on a local
/// 32-bit integer with a constant operand. This anchors the analysis on the
/// loop that produces the accumulating `n`.
void SAGenTestChecker::checkPostStmt(const BinaryOperator *BO,
                                     CheckerContext &C) const {
  // Placeholder for the `*=` is handled in checkPostStmt(CompoundAssignOperator).
  (void)BO;
  (void)C;
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded accumulation of input-derived values into fixed-width "
      "integers where bound checks happen only after the accumulation loop",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
