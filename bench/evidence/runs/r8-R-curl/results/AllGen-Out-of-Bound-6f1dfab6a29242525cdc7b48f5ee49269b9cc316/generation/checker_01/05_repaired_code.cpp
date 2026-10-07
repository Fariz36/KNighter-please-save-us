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
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/Stmt.h"
#include "knighter/roles.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool isAtLeastOne(const llvm::APSInt &I) {
  if (I.isSigned())
    return I.getSExtValue() >= 1;
  return I.getZExtValue() >= 1;
}

static bool isDeclRefToVar(const Expr *E, const VarDecl *VD) {
  if (!E || !VD)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E))
    return dyn_cast_or_null<VarDecl>(DRE->getDecl()) == VD;
  return false;
}

static const VarDecl *getBaseVarDecl(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      return VD;
  }

  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E))
    return getBaseVarDecl(ASE->getBase());

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref)
      return getBaseVarDecl(UO->getSubExpr());
  }

  return nullptr;
}

static bool isStringSearchCall(const CallExpr *CE) {
  if (!CE)
    return false;
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return false;
  const IdentifierInfo *ID = FD->getIdentifier();
  if (!ID)
    return false;
  return knighter::isRole("string_search", ID->getName());
}

static bool isStringSearchAssignment(const Stmt *S, const VarDecl *Ptr) {
  if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      const VarDecl *VD = dyn_cast<VarDecl>(D);
      if (VD != Ptr)
        continue;
      const Expr *Init = VD->getInit();
      if (!Init)
        continue;
      Init = Init->IgnoreParenCasts();
      if (const CallExpr *CE = dyn_cast<CallExpr>(Init))
        return isStringSearchCall(CE);
    }
    return false;
  }

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() != BO_Assign)
      return false;
    if (!isDeclRefToVar(BO->getLHS(), Ptr))
      return false;
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
    if (const CallExpr *CE = dyn_cast<CallExpr>(RHS))
      return isStringSearchCall(CE);
  }

  return false;
}

static bool isPointerAdvance(const Stmt *S, const VarDecl *Ptr,
                             CheckerContext &C) {
  if (!S)
    return false;

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc)
      return isDeclRefToVar(UO->getSubExpr(), Ptr);
  }

  if (const CompoundAssignOperator *CAO =
          dyn_cast<CompoundAssignOperator>(S)) {
    if (CAO->getOpcode() == BO_AddAssign &&
        isDeclRefToVar(CAO->getLHS(), Ptr)) {
      llvm::APSInt Val;
      return EvaluateExprToInt(Val, CAO->getRHS(), C) && Val.isOne();
    }
  }

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() != BO_Assign)
      return false;
    if (!isDeclRefToVar(BO->getLHS(), Ptr))
      return false;

    const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
    if (const BinaryOperator *Add = dyn_cast<BinaryOperator>(RHS)) {
      if (Add->getOpcode() != BO_Add)
        return false;

      const Expr *L = Add->getLHS()->IgnoreParenImpCasts();
      const Expr *R = Add->getRHS()->IgnoreParenImpCasts();
      llvm::APSInt Val;

      if (isDeclRefToVar(L, Ptr) && EvaluateExprToInt(Val, R, C) &&
          Val.isOne())
        return true;
      if (isDeclRefToVar(R, Ptr) && EvaluateExprToInt(Val, L, C) &&
          Val.isOne())
        return true;
    }
  }

  return false;
}

static bool isReadOfPtrIndexZero(const Expr *E, const VarDecl *Ptr,
                                 CheckerContext &C) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    if (getBaseVarDecl(ASE->getBase()) == Ptr) {
      llvm::APSInt Idx;
      if (EvaluateExprToInt(Idx, ASE->getIdx(), C) && Idx.isZero())
        return true;
    }
  }

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref && getBaseVarDecl(UO->getSubExpr()) == Ptr)
      return true;
  }

  return false;
}

static bool isFirstCharAfterDelim(const Stmt *S, const VarDecl *Ptr,
                                  const VarDecl *&Sep, CheckerContext &C) {
  if (!S)
    return false;

  if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      const VarDecl *VD = dyn_cast<VarDecl>(D);
      if (!VD)
        continue;
      const Expr *Init = VD->getInit();
      if (Init && isReadOfPtrIndexZero(Init, Ptr, C)) {
        Sep = VD;
        return true;
      }
    }
  }

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() != BO_Assign)
      return false;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS);
    if (!DRE)
      return false;

    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return false;

    if (isReadOfPtrIndexZero(BO->getRHS(), Ptr, C)) {
      Sep = VD;
      return true;
    }
  }

  return false;
}

struct FixedOffsetRead {
  const VarDecl *Ptr;
  const Expr *ReadExpr;
};

class FixedOffsetReadCollector
    : public RecursiveASTVisitor<FixedOffsetReadCollector> {
  CheckerContext &C;
  llvm::SmallVectorImpl<FixedOffsetRead> &Reads;

public:
  FixedOffsetReadCollector(CheckerContext &C,
                           llvm::SmallVectorImpl<FixedOffsetRead> &Reads)
      : C(C), Reads(Reads) {}

  bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
    if (const VarDecl *Ptr = getBaseVarDecl(ASE->getBase())) {
      llvm::APSInt Idx;
      if (EvaluateExprToInt(Idx, ASE->getIdx(), C) && isAtLeastOne(Idx))
        Reads.push_back({Ptr, ASE});
    }
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (UO->getOpcode() != UO_Deref)
      return true;

    const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
    if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Sub)) {
      if (BO->getOpcode() != BO_Add)
        return true;

      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

      if (const VarDecl *Ptr = getBaseVarDecl(L)) {
        llvm::APSInt Idx;
        if (EvaluateExprToInt(Idx, R, C) && isAtLeastOne(Idx))
          Reads.push_back({Ptr, UO});
      }

      if (const VarDecl *Ptr = getBaseVarDecl(R)) {
        llvm::APSInt Idx;
        if (EvaluateExprToInt(Idx, L, C) && isAtLeastOne(Idx))
          Reads.push_back({Ptr, UO});
      }
    }

    return true;
  }
};

static void collectFixedOffsetReads(
    const Expr *E, CheckerContext &C,
    llvm::SmallVectorImpl<FixedOffsetRead> &Reads) {
  if (!E)
    return;
  FixedOffsetReadCollector Collector(C, Reads);
  Collector.TraverseStmt(const_cast<Expr *>(E));
}

static bool containsFixedOffsetRead(const Expr *E, const VarDecl *Ptr,
                                    CheckerContext &C) {
  llvm::SmallVector<FixedOffsetRead, 4> Reads;
  collectFixedOffsetReads(E, C, Reads);
  for (const FixedOffsetRead &R : Reads) {
    if (R.Ptr == Ptr)
      return true;
  }
  return false;
}

static void flattenAnd(const Expr *E,
                       llvm::SmallVectorImpl<const Expr *> &Ops) {
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

static bool isSepGuard(const Expr *E, const VarDecl *Sep,
                       CheckerContext &C) {
  if (!E || !Sep)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E))
    return dyn_cast_or_null<VarDecl>(DRE->getDecl()) == Sep;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() != BO_NE)
      return false;

    const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
    llvm::APSInt Val;

    if (isDeclRefToVar(L, Sep) && EvaluateExprToInt(Val, R, C))
      return Val.isZero();
    if (isDeclRefToVar(R, Sep) && EvaluateExprToInt(Val, L, C))
      return Val.isZero();
  }

  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read", "Memory access")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  llvm::SmallVector<FixedOffsetRead, 8> Reads;
  collectFixedOffsetReads(CondE, C, Reads);
  if (Reads.empty())
    return;

  llvm::SmallPtrSet<const VarDecl *, 4> SeenPtrs;

  for (const FixedOffsetRead &Read : Reads) {
    const VarDecl *Ptr = Read.Ptr;
    if (!Ptr || SeenPtrs.count(Ptr))
      continue;
    SeenPtrs.insert(Ptr);

    bool FoundSearch = false;
    bool FoundAdvance = false;
    bool FoundSep = false;
    const VarDecl *Sep = nullptr;

    const Stmt *Cur = IS;
    while (Cur) {
      auto Parents = C.getASTContext().getParentMapContext().getParents(
          DynTypedNode::create(*Cur));
      if (Parents.empty())
        break;

      const Stmt *Parent = Parents[0].get<Stmt>();
      if (!Parent)
        break;

      if (const CompoundStmt *CS = dyn_cast<CompoundStmt>(Parent)) {
        for (const Stmt *S : CS->body()) {
          if (S == Cur)
            break;

          if (!FoundSearch && isStringSearchAssignment(S, Ptr))
            FoundSearch = true;
          if (!FoundAdvance && isPointerAdvance(S, Ptr, C))
            FoundAdvance = true;
          if (!FoundSep && isFirstCharAfterDelim(S, Ptr, Sep, C))
            FoundSep = true;
        }
      }

      Cur = Parent;
    }

    if (!FoundSearch || !FoundAdvance || !FoundSep || !Sep)
      continue;

    llvm::SmallVector<const Expr *, 8> Ops;
    flattenAnd(CondE, Ops);

    bool Guarded = false;
    for (const Expr *Op : Ops) {
      if (isSepGuard(Op, Sep, C)) {
        Guarded = true;
        continue;
      }

      if (!Guarded && containsFixedOffsetRead(Op, Ptr, C)) {
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N)
          return;

        auto Report = std::make_unique<PathSensitiveBugReport>(
            *BT,
            "Potential out-of-bounds read: missing NUL check after delimiter",
            N);
        Report->addRange(Op->getSourceRange());
        C.emitReport(std::move(Report));
        return;
      }
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects fixed-offset reads past the delimiter without checking the NUL "
      "terminator",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "string_search": {"names": ["strchr"], "description": "C string search function that returns a pointer to the first occurrence of a delimiter, or NULL if not found"}
}
*/
