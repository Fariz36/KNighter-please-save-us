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
#include "llvm/ADT/SmallVector.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "One-byte out-of-bounds read",
                       "Memory safety")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  const VarDecl *getVarDecl(const Expr *E) const;
  bool isZeroIndex(const Expr *Idx, CheckerContext &C) const;
  bool isPositiveIndex(const Expr *Idx, CheckerContext &C, int64_t &Val) const;
  bool isTruthinessCheck(const Expr *E, const VarDecl *V,
                         CheckerContext &C) const;
  void flattenAnd(const Expr *E,
                  llvm::SmallVectorImpl<const Expr *> &Ops) const;
  bool containsExpr(const Stmt *Root, const Stmt *Target) const;
  bool isIncrementOf(const Stmt *S, const VarDecl *V,
                     CheckerContext &C) const;
  bool isBaseZeroAccess(const Expr *E, const VarDecl *Base,
                        CheckerContext &C) const;
  bool isAssignSepFromBase0(const Stmt *S, const VarDecl *Sep,
                            const VarDecl *Base, CheckerContext &C) const;
  bool findOffendingComparison(const Stmt *S, CheckerContext &C,
                               const ArraySubscriptExpr *&OffendingRead,
                               const VarDecl *&BaseVar,
                               const VarDecl *&SepVar) const;
  void reportBug(const Expr *OffendingRead, CheckerContext &C) const;
};

} // end anonymous namespace

const VarDecl *SAGenTestChecker::getVarDecl(const Expr *E) const {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E))
    return dyn_cast<VarDecl>(DRE->getDecl());
  return nullptr;
}

bool SAGenTestChecker::isZeroIndex(const Expr *Idx,
                                   CheckerContext &C) const {
  if (!Idx)
    return false;
  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, Idx->IgnoreParenImpCasts(), C))
    return false;
  return EvalRes.isZero();
}

bool SAGenTestChecker::isPositiveIndex(const Expr *Idx, CheckerContext &C,
                                       int64_t &Val) const {
  if (!Idx)
    return false;
  llvm::APSInt EvalRes;
  if (!EvaluateExprToInt(EvalRes, Idx->IgnoreParenImpCasts(), C))
    return false;
  if (EvalRes.isSigned())
    Val = EvalRes.getSExtValue();
  else
    Val = EvalRes.getZExtValue();
  return Val > 0;
}

bool SAGenTestChecker::isTruthinessCheck(const Expr *E, const VarDecl *V,
                                         CheckerContext &C) const {
  if (!E || !V)
    return false;
  E = E->IgnoreParenImpCasts();

  if (getVarDecl(E) == V)
    return true;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_NE) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      if ((getVarDecl(L) == V && isZeroIndex(R, C)) ||
          (getVarDecl(R) == V && isZeroIndex(L, C)))
        return true;
    }
  }
  return false;
}

void SAGenTestChecker::flattenAnd(
    const Expr *E, llvm::SmallVectorImpl<const Expr *> &Ops) const {
  if (!E)
    return;
  E = E->IgnoreParenImpCasts();
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      flattenAnd(BO->getLHS(), Ops);
      flattenAnd(BO->getRHS(), Ops);
      return;
    }
  }
  Ops.push_back(E);
}

bool SAGenTestChecker::containsExpr(const Stmt *Root,
                                    const Stmt *Target) const {
  if (!Root || !Target)
    return false;
  if (Root == Target)
    return true;
  for (const Stmt *Child : Root->children()) {
    if (containsExpr(Child, Target))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isIncrementOf(const Stmt *S, const VarDecl *V,
                                     CheckerContext &C) const {
  if (!S || !V)
    return false;

  const Expr *E = dyn_cast<Expr>(S);
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc)
      return getVarDecl(UO->getSubExpr()) == V;
    return false;
  }

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_AddAssign) {
      if (getVarDecl(BO->getLHS()) != V)
        return false;
      llvm::APSInt EvalRes;
      if (EvaluateExprToInt(EvalRes, BO->getRHS()->IgnoreParenImpCasts(), C))
        return EvalRes.getLimitedValue() == 1;
    }
  }
  return false;
}

bool SAGenTestChecker::isBaseZeroAccess(const Expr *E, const VarDecl *Base,
                                        CheckerContext &C) const {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    const Expr *BaseE = ASE->getBase()->IgnoreParenImpCasts();
    const Expr *IdxE = ASE->getIdx()->IgnoreParenImpCasts();
    return getVarDecl(BaseE) == Base && isZeroIndex(IdxE, C);
  }

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref)
      return getVarDecl(UO->getSubExpr()->IgnoreParenImpCasts()) == Base;
  }
  return false;
}

bool SAGenTestChecker::isAssignSepFromBase0(const Stmt *S, const VarDecl *Sep,
                                            const VarDecl *Base,
                                            CheckerContext &C) const {
  if (!S || !Sep || !Base)
    return false;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (getVarDecl(LHS) == Sep)
        return isBaseZeroAccess(BO->getRHS(), Base, C);
    }
  }

  if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(D)) {
        if (VD == Sep && VD->hasInit())
          return isBaseZeroAccess(VD->getInit(), Base, C);
      }
    }
  }
  return false;
}

bool SAGenTestChecker::findOffendingComparison(
    const Stmt *S, CheckerContext &C,
    const ArraySubscriptExpr *&OffendingRead, const VarDecl *&BaseVar,
    const VarDecl *&SepVar) const {
  if (!S)
    return false;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(LHS)) {
        int64_t Val;
        if (isPositiveIndex(ASE->getIdx(), C, Val)) {
          const VarDecl *B = getVarDecl(ASE->getBase());
          const VarDecl *Sep = getVarDecl(RHS);
          if (B && Sep) {
            OffendingRead = ASE;
            BaseVar = B;
            SepVar = Sep;
            return true;
          }
        }
      }

      if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(RHS)) {
        int64_t Val;
        if (isPositiveIndex(ASE->getIdx(), C, Val)) {
          const VarDecl *B = getVarDecl(ASE->getBase());
          const VarDecl *Sep = getVarDecl(LHS);
          if (B && Sep) {
            OffendingRead = ASE;
            BaseVar = B;
            SepVar = Sep;
            return true;
          }
        }
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (findOffendingComparison(Child, C, OffendingRead, BaseVar, SepVar))
      return true;
  }
  return false;
}

void SAGenTestChecker::reportBug(const Expr *OffendingRead,
                                 CheckerContext &C) const {
  if (!OffendingRead)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Possible one-byte out-of-bounds read: delimiter byte is not checked "
      "for NUL before fixed-offset parse.",
      N);
  report->addRange(OffendingRead->getSourceRange());
  C.emitReport(std::move(report));
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *IfS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IfS)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;
  CondE = CondE->IgnoreParenImpCasts();

  const ArraySubscriptExpr *OffendingRead = nullptr;
  const VarDecl *BaseVar = nullptr;
  const VarDecl *SepVar = nullptr;
  if (!findOffendingComparison(CondE, C, OffendingRead, BaseVar, SepVar))
    return;

  llvm::SmallVector<const Expr *, 8> Ops;
  flattenAnd(CondE, Ops);

  bool foundOffending = false;
  bool hasGuard = false;
  for (const Expr *Op : Ops) {
    if (containsExpr(Op, OffendingRead)) {
      foundOffending = true;
      break;
    }
    if (isTruthinessCheck(Op, SepVar, C))
      hasGuard = true;
  }

  if (hasGuard || !foundOffending)
    return;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IfS, C);
  if (!CS)
    return;

  bool foundInc = false;
  bool foundAssign = false;
  for (const Stmt *S : CS->body()) {
    if (S == IfS)
      break;
    if (isIncrementOf(S, BaseVar, C))
      foundInc = true;
    if (isAssignSepFromBase0(S, SepVar, BaseVar, C))
      foundAssign = true;
  }

  if (foundInc && foundAssign)
    reportBug(OffendingRead, C);
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects one-byte out-of-bounds reads when parsing a NUL-terminated "
      "string after a delimiter search without checking the delimiter byte.",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["curlx_dyn_ptr"], "description": "returns the received response buffer to parse"},
  "search": {"names": ["strchr"], "description": "finds the first occurrence of a character in a NUL-terminated string"},
  "character_classifier": {"names": ["ISDIGIT"], "description": "tests whether a character is a decimal digit"},
  "error_setter": {"names": ["failf"], "description": "records/reports an error message"},
  "numeric_parser": {"names": ["curlx_str_number"], "description": "parses a number from a string"}
}
*/
