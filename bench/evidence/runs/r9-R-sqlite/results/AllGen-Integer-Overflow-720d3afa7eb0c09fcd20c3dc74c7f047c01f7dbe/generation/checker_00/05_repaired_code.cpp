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
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow in Cache Size Computation",
                       "Integer Overflow")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  const Expr *findResizeCount(const Stmt *Cond, CheckerContext &C) const;
  const Expr *extractCountFromSizeExpr(const Expr *E) const;
  bool isNarrowOverflowProne(const Expr *Count, CheckerContext &C) const;
  bool containsArithmetic(const Expr *E) const;
  bool containsSizeof(const Expr *E) const;
  bool isSizeofExpr(const Expr *E) const;
  bool isIntegerLiteral(const Expr *E) const;
  bool isAllocatedSizeCall(const CallExpr *CE) const;
  void reportBug(const Expr *Count, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *SizeExpr = findResizeCount(Condition, C);
  if (!SizeExpr)
    return;

  if (!containsSizeof(SizeExpr))
    return;

  const Expr *Count = extractCountFromSizeExpr(SizeExpr);
  if (!Count)
    return;

  if (!isNarrowOverflowProne(Count, C))
    return;

  reportBug(Count, C);
}

const Expr *SAGenTestChecker::findResizeCount(const Stmt *Cond,
                                              CheckerContext &C) const {
  if (!Cond)
    return nullptr;

  const Expr *E = dyn_cast<Expr>(Cond);
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();

    // Recurse through logical operators.
    if (Op == BO_LOr || Op == BO_LAnd) {
      if (const Expr *L = findResizeCount(BO->getLHS(), C))
        return L;
      if (const Expr *R = findResizeCount(BO->getRHS(), C))
        return R;
      return nullptr;
    }

    // Look for comparisons against the allocated-size query.
    if (Op == BO_GT || Op == BO_GE || Op == BO_LT || Op == BO_LE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      if (const CallExpr *CE = dyn_cast<CallExpr>(LHS)) {
        if (isAllocatedSizeCall(CE))
          return RHS;
      }
      if (const CallExpr *CE = dyn_cast<CallExpr>(RHS)) {
        if (isAllocatedSizeCall(CE))
          return LHS;
      }
    }
  }

  return nullptr;
}

const Expr *SAGenTestChecker::extractCountFromSizeExpr(const Expr *E) const {
  if (!E)
    return nullptr;

  E = E->IgnoreParenCasts();

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_Mul || Op == BO_Div) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();

      if (isSizeofExpr(RHS) || isIntegerLiteral(RHS))
        return extractCountFromSizeExpr(LHS);
      if (isSizeofExpr(LHS) || isIntegerLiteral(LHS))
        return extractCountFromSizeExpr(RHS);

      if (const Expr *L = extractCountFromSizeExpr(LHS))
        return L;
      if (const Expr *R = extractCountFromSizeExpr(RHS))
        return R;
    }
  }

  if (!isSizeofExpr(E) && !isIntegerLiteral(E))
    return E;

  return nullptr;
}

bool SAGenTestChecker::isNarrowOverflowProne(const Expr *Count,
                                             CheckerContext &C) const {
  if (!Count)
    return false;

  Count = Count->IgnoreParenImpCasts();
  ASTContext &AC = C.getASTContext();

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Count)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      QualType QT = VD->getType();
      if (!QT->isIntegerType())
        return false;

      unsigned Width = AC.getIntWidth(QT);
      if (Width >= 64)
        return false;

      const Expr *Init = VD->getInit();
      if (!Init)
        return false;

      Init = Init->IgnoreParenImpCasts();
      if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Init)) {
        BinaryOperator::Opcode Op = BO->getOpcode();
        if (Op == BO_Add || Op == BO_Sub || Op == BO_Mul ||
            Op == BO_Div || Op == BO_Rem) {
          QualType InitTy = Init->getType();
          if (InitTy->isIntegerType() && AC.getIntWidth(InitTy) < 64)
            return true;
        }
      } else if (isa<ConditionalOperator>(Init)) {
        QualType InitTy = Init->getType();
        if (InitTy->isIntegerType() && AC.getIntWidth(InitTy) < 64)
          return true;
      }
      return false;
    }
  }

  // Not a simple declaration reference: examine the expression type and shape.
  QualType QT = Count->getType();
  if (QT->isIntegerType() && AC.getIntWidth(QT) < 64) {
    if (containsArithmetic(Count))
      return true;
  }
  return false;
}

bool SAGenTestChecker::containsArithmetic(const Expr *E) const {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_Add || Op == BO_Sub || Op == BO_Mul ||
        Op == BO_Div || Op == BO_Rem)
      return true;
  }

  if (isa<ConditionalOperator>(E))
    return true;

  for (const Stmt *Child : E->children()) {
    if (const Expr *CE = dyn_cast<Expr>(Child)) {
      if (containsArithmetic(CE))
        return true;
    }
  }
  return false;
}

bool SAGenTestChecker::containsSizeof(const Expr *E) const {
  if (!E)
    return false;

  E = E->IgnoreParenCasts();
  if (isSizeofExpr(E))
    return true;

  for (const Stmt *Child : E->children()) {
    if (const Expr *CE = dyn_cast<Expr>(Child)) {
      if (containsSizeof(CE))
        return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isSizeofExpr(const Expr *E) const {
  if (!E)
    return false;

  E = E->IgnoreParenCasts();
  if (const UnaryExprOrTypeTraitExpr *UETT =
          dyn_cast<UnaryExprOrTypeTraitExpr>(E)) {
    return UETT->getKind() == UETT_SizeOf;
  }
  return false;
}

bool SAGenTestChecker::isIntegerLiteral(const Expr *E) const {
  if (!E)
    return false;

  E = E->IgnoreParenCasts();
  return isa<IntegerLiteral>(E);
}

bool SAGenTestChecker::isAllocatedSizeCall(const CallExpr *CE) const {
  if (!CE)
    return false;

  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    return knighter::declIsRole(FD, "allocated_size");
  }
  return false;
}

void SAGenTestChecker::reportBug(const Expr *Count, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto BR = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential integer overflow in cache element count; widen count to "
      "64-bit before multiplying by element size.",
      N);
  BR->addRange(Count->getSourceRange());
  C.emitReport(std::move(BR));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potential integer overflow in cache element count computation "
      "before size multiplication",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocated_size": {
    "names": ["sqlite3MallocSize"],
    "description": "returns the current allocated size of a memory region; used to decide whether a resize is needed"
  },
  "reallocator": {
    "names": ["sqlite3Realloc"],
    "description": "resizes a memory region; its size argument must be large enough for the element count"
  },
  "null_on_failure": {
    "names": ["sqlite3Realloc"],
    "description": "may return NULL on failure; its result is checked before use"
  },
  "initializer": {
    "names": ["memset"],
    "description": "initializes a memory region to zero; the size must match the allocated size"
  }
}
*/
