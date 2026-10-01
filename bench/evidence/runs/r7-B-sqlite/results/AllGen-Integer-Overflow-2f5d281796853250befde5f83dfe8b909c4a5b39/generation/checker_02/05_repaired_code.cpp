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
#include "clang/AST/Decl.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallPtrSet.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class LoopOverflowVisitor : public RecursiveASTVisitor<LoopOverflowVisitor> {
  ASTContext &Ctx;
  BugReporter &BR;
  const BugType *BT;
  llvm::SmallPtrSet<const VarDecl *, 16> LoopVars;
  llvm::DenseSet<unsigned> ReportedLocs;

public:
  LoopOverflowVisitor(ASTContext &Ctx, BugReporter &BR, const BugType *BT)
      : Ctx(Ctx), BR(BR), BT(BT) {}

  bool VisitForStmt(ForStmt *FS) {
    collectLoopVars(FS->getInit());
    collectLoopVars(FS->getCond());
    collectLoopVars(FS->getInc());
    collectLoopVars(FS->getBody());
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->isComparisonOp()) {
      checkComparison(BO);
    }
    return true;
  }

private:
  void collectLoopVars(Stmt *S) {
    if (!S)
      return;
    struct Collector : RecursiveASTVisitor<Collector> {
      LoopOverflowVisitor &Parent;
      Collector(LoopOverflowVisitor &P) : Parent(P) {}
      bool VisitBinaryOperator(BinaryOperator *BO) {
        if (BO->isAssignmentOp()) {
          Parent.recordVar(BO->getLHS());
        }
        return true;
      }
      bool VisitUnaryOperator(UnaryOperator *UO) {
        if (UO->isIncrementDecrementOp()) {
          Parent.recordVar(UO->getSubExpr());
        }
        return true;
      }
    } C(*this);
    C.TraverseStmt(S);
  }

  void recordVar(const Expr *E) {
    if (!E)
      return;
    E = E->IgnoreParenImpCasts();
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
    if (!DRE)
      return;
    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return;
    QualType QT = VD->getType().getCanonicalType();
    if (QT->isIntegerType() && QT->isSignedIntegerType() &&
        Ctx.getTypeSize(QT) == 32) {
      LoopVars.insert(VD);
    }
  }

  bool referencesLoopVar(const Expr *E) const {
    if (!E)
      return false;
    E = E->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (LoopVars.count(VD))
          return true;
      }
    }
    for (const Stmt *Child : E->children()) {
      if (const Expr *ChildE = dyn_cast<Expr>(Child)) {
        if (referencesLoopVar(ChildE))
          return true;
      }
    }
    return false;
  }

  void checkComparison(BinaryOperator *BO) {
    Expr *LHS = BO->getLHS()->IgnoreParens();
    Expr *RHS = BO->getRHS()->IgnoreParens();

    checkComparisonSide(LHS, RHS, BO);
    checkComparisonSide(RHS, LHS, BO);
  }

  void checkComparisonSide(const Expr *E, const Expr *Other,
                           BinaryOperator *BO) {
    QualType OtherTy = Other->getType();
    if (!OtherTy->isIntegerType() || Ctx.getTypeSize(OtherTy) != 64)
      return;

    const Expr *Inner = E->IgnoreParenImpCasts();
    QualType InnerTy = Inner->getType();
    if (!InnerTy->isIntegerType() || !InnerTy->isSignedIntegerType() ||
        Ctx.getTypeSize(InnerTy) != 32)
      return;

    const auto *Bin = dyn_cast<BinaryOperator>(Inner);
    if (!Bin)
      return;

    BinaryOperator::Opcode Op = Bin->getOpcode();
    if (Op != BO_Add && Op != BO_Sub && Op != BO_Mul)
      return;

    if (!referencesLoopVar(Bin))
      return;

    report(BO);
  }

  void report(BinaryOperator *BO) {
    SourceLocation Loc = BO->getOperatorLoc();
    if (Loc.isInvalid())
      return;
    unsigned Raw = Loc.getRawEncoding();
    if (!ReportedLocs.insert(Raw).second)
      return;

    PathDiagnosticLocation PL(Loc, Ctx.getSourceManager());
    auto R = std::make_unique<BasicBugReport>(
        *BT, "32-bit loop counter in 64-bit comparison may overflow; use i64.",
        PL);
    BR.emitReport(std::move(R));
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow", "Loop counter overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  if (!D)
    return;
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  ASTContext &Ctx = Mgr.getASTContext();
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  LoopOverflowVisitor Visitor(Ctx, BR, BT.get());
  Visitor.TraverseStmt(const_cast<Stmt *>(Body));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects 32-bit loop counter overflow in 64-bit comparisons",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
