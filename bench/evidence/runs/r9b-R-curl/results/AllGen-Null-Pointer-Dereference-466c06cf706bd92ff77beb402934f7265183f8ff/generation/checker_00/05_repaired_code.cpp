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
#include "clang/Basic/SourceManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/ArrayRef.h"
#include <memory>
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Returns true when E is exactly a reference to parameter P (after casts/parens).
static bool isParamRef(const Expr *E, const ParmVarDecl *P) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  return DRE && DRE->getDecl() == P;
}

// Returns true if E dereferences parameter P via ->, *, or [].
static bool isDerefOfParam(const Expr *E, const ParmVarDecl *P) {
  if (!E)
    return false;

  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (ME->isArrow() && isParamRef(ME->getBase(), P))
      return true;
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref && isParamRef(UO->getSubExpr(), P))
      return true;
  }

  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    if (isParamRef(ASE->getBase(), P))
      return true;
  }

  return false;
}

class DerefCollector : public RecursiveASTVisitor<DerefCollector> {
public:
  const ParmVarDecl *P;
  SmallVector<const Expr *, 8> Derefs;

  explicit DerefCollector(const ParmVarDecl *P) : P(P) {}

  bool VisitMemberExpr(MemberExpr *ME) {
    if (isDerefOfParam(ME, P))
      Derefs.push_back(ME);
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (isDerefOfParam(UO, P))
      Derefs.push_back(UO);
    return true;
  }

  bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
    if (isDerefOfParam(ASE, P))
      Derefs.push_back(ASE);
    return true;
  }
};

class IfCollector : public RecursiveASTVisitor<IfCollector> {
public:
  SmallVector<const IfStmt *, 8> Ifs;

  bool VisitIfStmt(IfStmt *IS) {
    Ifs.push_back(IS);
    return true;
  }
};

static bool stmtContains(const Stmt *Parent, const Stmt *Child) {
  if (!Parent || !Child)
    return false;
  if (Parent == Child)
    return true;
  for (const Stmt *S : Parent->children()) {
    if (stmtContains(S, Child))
      return true;
  }
  return false;
}

static bool containsReturnOrAbort(const Stmt *S, ASTContext &Ctx) {
  if (!S)
    return false;

  if (isa<ReturnStmt>(S))
    return true;

  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (knighter::callExprIsRole(CE, "aborting_assert", Ctx))
      return true;
  }

  for (const Stmt *Child : S->children()) {
    if (containsReturnOrAbort(Child, Ctx))
      return true;
  }
  return false;
}

struct NullGuardInfo {
  bool IsNullCheck = false;
  const Stmt *NonNullBranch = nullptr;
  const Stmt *NullBranch = nullptr;
};

static bool isNullConstant(const Expr *E, ASTContext &Ctx) {
  return E && E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
}

static NullGuardInfo getNullGuardInfo(const IfStmt *IS,
                                      const ParmVarDecl *P,
                                      ASTContext &Ctx) {
  NullGuardInfo Info;
  const Expr *Cond = IS->getCond();
  if (!Cond)
    return Info;

  Cond = Cond->IgnoreParenImpCasts();

  // Case: !P
  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot && isParamRef(UO->getSubExpr(), P)) {
      Info.IsNullCheck = true;
      Info.NullBranch = IS->getThen();
      Info.NonNullBranch = IS->getElse();
      return Info;
    }
  }

  // Case: P
  if (isParamRef(Cond, P)) {
    Info.IsNullCheck = true;
    Info.NonNullBranch = IS->getThen();
    Info.NullBranch = IS->getElse();
    return Info;
  }

  // Case: P == NULL, P != NULL, P == 0, P != 0
  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      const bool LHSIsParam = isParamRef(LHS, P);
      const bool RHSIsParam = isParamRef(RHS, P);
      const bool LHSIsNull = isNullConstant(LHS, Ctx);
      const bool RHSIsNull = isNullConstant(RHS, Ctx);

      if ((LHSIsParam && RHSIsNull) || (RHSIsParam && LHSIsNull)) {
        Info.IsNullCheck = true;
        if (Op == BO_EQ) {
          // P == NULL: true means null.
          Info.NullBranch = IS->getThen();
          Info.NonNullBranch = IS->getElse();
        } else {
          // P != NULL: true means non-null.
          Info.NonNullBranch = IS->getThen();
          Info.NullBranch = IS->getElse();
        }
        return Info;
      }
    }
  }

  return Info;
}

static bool isGuardedByIf(const IfStmt *IS,
                          const ParmVarDecl *P,
                          const Expr *D,
                          ASTContext &Ctx) {
  NullGuardInfo Info = getNullGuardInfo(IS, P, Ctx);
  if (!Info.IsNullCheck)
    return false;

  // Case 1: the first dereference is inside the non-null branch.
  if (Info.NonNullBranch && stmtContains(Info.NonNullBranch, D))
    return true;

  // Case 2: the if statement is before the first dereference and its
  // null-handling branch returns/aborts.
  SourceManager &SM = Ctx.getSourceManager();
  SourceLocation IfEnd = IS->getEndLoc();
  SourceLocation DerefBegin = D->getBeginLoc();

  if (IfEnd.isValid() && DerefBegin.isValid() &&
      SM.isBeforeInTranslationUnit(IfEnd, DerefBegin)) {
    if (Info.NullBranch && containsReturnOrAbort(Info.NullBranch, Ctx))
      return true;
  }

  return false;
}

static const Expr *getFirstDeref(ArrayRef<const Expr *> Derefs,
                                 ASTContext &Ctx) {
  if (Derefs.empty())
    return nullptr;

  SourceManager &SM = Ctx.getSourceManager();
  const Expr *First = Derefs[0];

  for (const Expr *E : Derefs) {
    if (!E->getBeginLoc().isValid() || !First->getBeginLoc().isValid())
      continue;
    if (SM.isBeforeInTranslationUnit(E->getBeginLoc(), First->getBeginLoc()))
      First = E;
  }

  return First;
}

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "NULL Pointer Dereference", "Null Dereference")) {}

  void checkASTCodeBody(const Decl *D,
                        AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D,
                                        AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  if (!knighter::declIsRole(FD, "duplicator"))
    return;

  ASTContext &Ctx = Mgr.getASTContext();
  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  for (ParmVarDecl *Param : FD->parameters()) {
    const ParmVarDecl *P = Param;

    if (!P->getType()->isPointerType())
      continue;

    DerefCollector DC(P);
    DC.TraverseStmt(Body);

    if (DC.Derefs.empty())
      continue;

    const Expr *FirstDeref = getFirstDeref(DC.Derefs, Ctx);
    if (!FirstDeref)
      continue;

    IfCollector IC;
    IC.TraverseStmt(Body);

    bool Guarded = false;
    for (const IfStmt *IS : IC.Ifs) {
      if (isGuardedByIf(IS, P, FirstDeref, Ctx)) {
        Guarded = true;
        break;
      }
    }

    if (!Guarded) {
      PathDiagnosticLocation Loc =
          PathDiagnosticLocation::createBegin(FirstDeref, BR.getSourceManager(),
                                              nullptr);
      auto Report = std::make_unique<BasicBugReport>(
          *BT,
          "Duplicator dereferences source pointer before NULL check",
          Loc);
      BR.emitReport(std::move(Report));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects duplicator functions that dereference a source pointer before "
      "checking it for NULL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "duplicator": {"names": ["curl_url_dup", "DUP"], "description": "duplicates an object; returns a new copy or NULL on failure"},
  "allocator": {"names": ["curlx_calloc"], "description": "allocates zero-initialized memory"},
  "cleanup": {"names": ["curl_url_cleanup"], "description": "frees an object or releases resources"},
  "aborting_assert": {"names": ["DEBUGASSERT"], "description": "macro that aborts execution when its condition is false, so the argument is non-null afterwards"}
}
*/
