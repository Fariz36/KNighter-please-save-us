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
#include "clang/AST/ParentMapContext.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow in Loop Accumulator",
                       "Integer Overflow")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Find the enclosing WhileStmt for a statement, searching within the
  // function body.
  const WhileStmt *findEnclosingWhile(const Stmt *S) const;

  // Check if the loop body has the pattern:
  //   X += (c - 'a')*mult; mult *= 26;
  // Returns the name of the accumulator variable if found, nullptr otherwise.
  const VarDecl *findOverflowProneAccumulator(const WhileStmt *WS) const;

  // Does the while loop contain a bounds check against `nOut` (or any variable
  // named "nOut") inside the loop between the accumulation and mult update?
  bool loopHasInnerBoundsCheck(const WhileStmt *WS) const;

  // Is the given variable declared with a narrow integer type?
  bool isNarrowIntegerType(QualType QT) const;
};

//===----------------------------------------------------------------------===//

const WhileStmt *
SAGenTestChecker::findEnclosingWhile(const Stmt *S) const {
  if (!S) return nullptr;
  // Walk up the parent chain looking for a WhileStmt.
  const Stmt *Cur = S;
  // Use the current TU's context to walk up parents via the ParentMap.
  // Unfortunately we don't have direct ParentMap access here without
  // AnalysisManager. Walk using dynamic dispatch.
  // Since we cannot get ParentMap easily from a plain Stmt, we instead rely
  // on callers giving us the enclosing function body we can scan.
  (void)Cur;
  return nullptr;
}

bool SAGenTestChecker::isNarrowIntegerType(QualType QT) const {
  if (!QT->isIntegerType())
    return false;
  if (QT->isBooleanType())
    return false;
  // Use ASTContext via an Expr if available - we approximate using type size.
  // We can't get ASTContext here without a node, so check for common variants:
  const BuiltinType *BT = QT->getAs<BuiltinType>();
  if (!BT)
    return false;
  switch (BT->getKind()) {
    case BuiltinType::Char_S:
    case BuiltinType::Char_U:
    case BuiltinType::SChar:
    case BuiltinType::UChar:
    case BuiltinType::Short:
    case BuiltinType::UShort:
    case BuiltinType::Int:
    case BuiltinType::UInt:
      return true;
    default:
      return false;
  }
}

// Recursively collect all CompoundAssignOperator / BinaryOperator statements.
static void collectStmts(const Stmt *S,
                         SmallVectorImpl<const Stmt *> &Out) {
  if (!S) return;
  Out.push_back(S);
  for (const Stmt *Child : S->children()) {
    if (Child) collectStmts(Child, Out);
  }
}

// Recursively check if the loop body contains an IfStmt that compares a
// variable named "nOut" (or a variable not equal to the accumulator) with
// an accumulator, i.e. a bounds check.
static bool containsBoundsCheckAgainst(const Stmt *S,
                                       const VarDecl *Accumulator) {
  if (!S) return false;
  if (const auto *IS = dyn_cast<IfStmt>(S)) {
    if (const Expr *Cond = IS->getCond()) {
      // Look for any DeclRefExpr in the condition that is NOT the accumulator.
      SmallVector<const Stmt *, 16> Sub;
      collectStmts(Cond, Sub);
      bool HasOtherVar = false;
      for (const Stmt *SubS : Sub) {
        if (const auto *DRE = dyn_cast<DeclRefExpr>(SubS)) {
          const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
          if (VD && VD != Accumulator)
            HasOtherVar = true;
        }
      }
      if (HasOtherVar)
        return true;
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsBoundsCheckAgainst(Child, Accumulator))
      return true;
  }
  return false;
}

const VarDecl *
SAGenTestChecker::findOverflowProneAccumulator(const WhileStmt *WS) const {
  if (!WS) return nullptr;
  const Stmt *Body = WS->getBody();
  if (!Body) return nullptr;

  // Flatten body to search for the pattern.
  SmallVector<const Stmt *, 32> Stmts;
  collectStmts(Body, Stmts);

  // Look for compound assignment `X += (c - 'a') * mult` where X's RHS
  // involves a multiplication.
  const VarDecl *Accumulator = nullptr;
  for (const Stmt *S : Stmts) {
    const auto *CAO = dyn_cast<CompoundAssignOperator>(S);
    if (!CAO) continue;
    if (CAO->getOpcode() != BO_Add) continue;
    const Expr *RHS = CAO->getRHS();
    if (!RHS) continue;
    // Check RHS is a multiplication.
    const auto *BO = dyn_cast<BinaryOperator>(RHS->IgnoreParenCasts());
    if (!BO || BO->getOpcode() != BO_Mul) continue;
    // LHS of CAO must be a DeclRefExpr of an integer variable.
    const Expr *LHS = CAO->getLHS()->IgnoreParenCasts();
    const auto *DRE = dyn_cast<DeclRefExpr>(LHS);
    if (!DRE) continue;
    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD) continue;
    if (!isNarrowIntegerType(VD->getType())) continue;
    Accumulator = VD;
    break;
  }
  return Accumulator;
}

bool SAGenTestChecker::loopHasInnerBoundsCheck(const WhileStmt *WS) const {
  if (!WS) return false;
  const VarDecl *Acc = findOverflowProneAccumulator(WS);
  if (!Acc) return false;
  return containsBoundsCheckAgainst(WS->getBody(), Acc);
}

//===----------------------------------------------------------------------===//
// Match a variable name from the DeclRefExpr of the memset size argument or
// the LHS of the pattern.
//===----------------------------------------------------------------------===//

static const VarDecl *getDeclFromExpr(const Expr *E) {
  if (!E) return nullptr;
  E = E->IgnoreParenCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<VarDecl>(DRE->getDecl());
  }
  return nullptr;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;
  if (!ExprHasName(OriginExpr, "memset", C))
    return;

  // Get the size argument (2nd arg, index 1).
  if (Call.getNumArgs() < 3)
    return;
  const Expr *SizeArg = Call.getArgExpr(1);
  if (!SizeArg)
    return;

  // The size argument should reference an accumulator variable.
  const VarDecl *SizeVar = getDeclFromExpr(SizeArg);
  if (!SizeVar)
    return;

  // Walk up to find the enclosing WhileStmt. We don't have a ParentMap here,
  // so instead we get the function body from the LocationContext and scan
  // for the pattern.
  const LocationContext *LCtx = Call.getLocationContext();
  if (!LCtx)
    return;
  const Decl *D = LCtx->getDecl();
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  // Collect all WhileStmts in the function body.
  SmallVector<const Stmt *, 64> AllStmts;
  collectStmts(Body, AllStmts);

  for (const Stmt *S : AllStmts) {
    const auto *WS = dyn_cast<WhileStmt>(S);
    if (!WS) continue;

    const VarDecl *Acc = findOverflowProneAccumulator(WS);
    if (!Acc) continue;
    if (Acc != SizeVar) continue;

    // Does this loop lack a bounds check that would prevent overflow?
    if (loopHasInnerBoundsCheck(WS))
      continue;

    // Found the bug: the accumulator variable used as memset size is
    // accumulated with a multiply-accumulate pattern inside a loop, is
    // a narrow integer type, and there is no inner bounds check to
    // catch overflow before it propagates into the memset size.
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Integer overflow in loop accumulator used as memset size",
        N);
    report->addRange(SizeArg->getSourceRange());
    C.emitReport(std::move(report));
    return;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in a narrow-integer loop accumulator that "
      "flows into a memset size without an inner bounds check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
