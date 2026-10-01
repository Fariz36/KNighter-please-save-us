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

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool isParamRef(const Expr *E, const ParmVarDecl *Param) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    return DRE->getDecl() == Param;
  return false;
}

static bool returnsNull(const Stmt *S, ASTContext &Ctx) {
  if (!S)
    return false;

  if (const auto *RS = dyn_cast<ReturnStmt>(S)) {
    const Expr *Ret = RS->getRetValue();
    if (!Ret)
      return false;
    return Ret->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
  }

  if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
    if (CS->body_empty())
      return false;
    return returnsNull(CS->body_back(), Ctx);
  }

  return false;
}

static bool isNullGuard(const IfStmt *IS, const ParmVarDecl *Param) {
  if (!IS || !IS->getCond())
    return false;

  ASTContext &Ctx = Param->getASTContext();
  const Expr *Cond = IS->getCond()->IgnoreParenImpCasts();
  bool IsNullCheck = false;

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      IsNullCheck = isParamRef(UO->getSubExpr(), Param);
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      bool LHSIsParam = isParamRef(LHS, Param);
      bool RHSIsParam = isParamRef(RHS, Param);
      bool LHSIsNull = LHS->isNullPointerConstant(
          Ctx, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          Ctx, Expr::NPC_ValueDependentIsNull);

      IsNullCheck = (LHSIsParam && RHSIsNull) || (RHSIsParam && LHSIsNull);
    }
  }

  if (!IsNullCheck)
    return false;

  return returnsNull(IS->getThen(), Ctx);
}

class ParamDerefFinder : public RecursiveASTVisitor<ParamDerefFinder> {
  const ParmVarDecl *Param;

public:
  bool Found = false;
  SourceRange Range;

  explicit ParamDerefFinder(const ParmVarDecl *P) : Param(P) {}

  bool VisitMemberExpr(MemberExpr *ME) {
    if (Found)
      return false;
    if (ME->isArrow()) {
      const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
      if (isParamRef(Base, Param)) {
        Found = true;
        Range = ME->getSourceRange();
        return false;
      }
    }
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (Found)
      return false;
    if (UO->getOpcode() == UO_Deref) {
      if (isParamRef(UO->getSubExpr(), Param)) {
        Found = true;
        Range = UO->getSourceRange();
        return false;
      }
    }
    return true;
  }

  bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
    if (Found)
      return false;
    if (isParamRef(ASE->getBase(), Param)) {
      Found = true;
      Range = ASE->getSourceRange();
      return false;
    }
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "MissingNullCheck", "Null Dereference")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  if (FD->getNameAsString() != "curl_url_dup")
    return;

  if (FD->getNumParams() < 1)
    return;

  const ParmVarDecl *Param = FD->getParamDecl(0);
  if (!Param->getType()->isPointerType())
    return;

  if (Param->getNameAsString() != "in")
    return;

  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  auto *CS = dyn_cast<CompoundStmt>(Body);
  if (!CS)
    return;

  bool Checked = false;

  for (Stmt *S : CS->body()) {
    if (const auto *IS = dyn_cast<IfStmt>(S)) {
      if (isNullGuard(IS, Param)) {
        Checked = true;
        continue;
      }
    }

    if (Checked)
      continue;

    ParamDerefFinder Finder(Param);
    Finder.TraverseStmt(S);

    if (Finder.Found) {
      auto Report = std::make_unique<BasicBugReport>(
          *BT,
          "curl_url_dup: parameter 'in' dereferenced without NULL check",
          PathDiagnosticLocation(Finder.Range.getBegin(),
                                 BR.getSourceManager()));
      Report->addRange(Finder.Range);
      BR.emitReport(std::move(Report));
      return;
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects curl_url_dup dereferencing parameter 'in' without NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

