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
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

struct UnsafeDivision {
  const FieldDecl *Field;
  SourceLocation Loc;
};

static const Expr *stripExpr(const Expr *E) {
  if (!E)
    return nullptr;
  return E->IgnoreParenImpCasts();
}

static bool isZeroLiteral(const Expr *E) {
  E = stripExpr(E);
  if (const auto *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue() == 0;
  return false;
}

static bool isOneLiteral(const Expr *E) {
  E = stripExpr(E);
  if (const auto *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue() == 1;
  return false;
}

static bool exprIsField(const Expr *E, const FieldDecl *F) {
  E = stripExpr(E);
  const auto *ME = dyn_cast<MemberExpr>(E);
  if (!ME)
    return false;
  const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  return FD == F;
}

static bool isNonZeroGuard(const Expr *E, const FieldDecl *F) {
  E = stripExpr(E);
  if (!E)
    return false;

  // if (F) { ... }
  if (exprIsField(E, F))
    return true;

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    const Expr *L = stripExpr(BO->getLHS());
    const Expr *R = stripExpr(BO->getRHS());

    if (Op == BO_NE) {
      if ((exprIsField(L, F) && isZeroLiteral(R)) ||
          (exprIsField(R, F) && isZeroLiteral(L)))
        return true;
    }
    if (Op == BO_GT) {
      if (exprIsField(L, F) && isZeroLiteral(R))
        return true;
    }
    if (Op == BO_LT) {
      if (isZeroLiteral(L) && exprIsField(R, F))
        return true;
    }
    if (Op == BO_GE) {
      if (exprIsField(L, F) && isOneLiteral(R))
        return true;
    }
    if (Op == BO_LE) {
      if (isOneLiteral(L) && exprIsField(R, F))
        return true;
    }

    // For "A && B", a guard in either operand is enough.
    if (Op == BO_LAnd) {
      if (isNonZeroGuard(L, F) || isNonZeroGuard(R, F))
        return true;
    }

    // For "A || B", every path must imply the guard.
    if (Op == BO_LOr) {
      if (isNonZeroGuard(L, F) && isNonZeroGuard(R, F))
        return true;
    }
  }

  return false;
}

static bool conditionChecksParamZero(const Expr *Cond, const ParmVarDecl *P,
                                     bool &ImpliesZero) {
  Cond = stripExpr(Cond);
  if (!Cond)
    return false;

  // !P
  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = stripExpr(UO->getSubExpr());
      if (const auto *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        if (dyn_cast<ParmVarDecl>(DRE->getDecl()) == P) {
          ImpliesZero = true;
          return true;
        }
      }
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *L = stripExpr(BO->getLHS());
      const Expr *R = stripExpr(BO->getRHS());

      const auto *LHSDRE = dyn_cast<DeclRefExpr>(L);
      const auto *RHSDRE = dyn_cast<DeclRefExpr>(R);

      const auto *LP = LHSDRE ? dyn_cast<ParmVarDecl>(LHSDRE->getDecl()) : nullptr;
      const auto *RP = RHSDRE ? dyn_cast<ParmVarDecl>(RHSDRE->getDecl()) : nullptr;

      if (LP == P && isZeroLiteral(R)) {
        ImpliesZero = (Op == BO_EQ);
        return true;
      }
      if (RP == P && isZeroLiteral(L)) {
        ImpliesZero = (Op == BO_EQ);
        return true;
      }
    }
  }

  return false;
}

class ReturnOrAbortFinder : public RecursiveASTVisitor<ReturnOrAbortFinder> {
  ASTContext &AC;
  bool Found = false;

public:
  explicit ReturnOrAbortFinder(ASTContext &AC) : AC(AC) {}

  bool VisitReturnStmt(ReturnStmt *RS) {
    Found = true;
    return false;
  }

  bool VisitCallExpr(CallExpr *CE) {
    if (knighter::callExprIsRole(CE, "aborting_assert", AC)) {
      Found = true;
      return false;
    }
    return true;
  }

  bool found() const { return Found; }
};

static bool containsReturnOrAbort(const Stmt *S, ASTContext &AC) {
  if (!S)
    return false;
  ReturnOrAbortFinder Finder(AC);
  Finder.TraverseStmt(const_cast<Stmt *>(S));
  return Finder.found();
}

class ErrorSetterFinder : public RecursiveASTVisitor<ErrorSetterFinder> {
  ASTContext &AC;
  bool Found = false;

public:
  explicit ErrorSetterFinder(ASTContext &AC) : AC(AC) {}

  bool VisitCallExpr(CallExpr *CE) {
    if (knighter::callExprIsRole(CE, "error_setter", AC)) {
      Found = true;
      return false;
    }
    return true;
  }

  bool found() const { return Found; }
};

static bool containsErrorSetter(const Stmt *S, ASTContext &AC) {
  if (!S)
    return false;
  ErrorSetterFinder Finder(AC);
  Finder.TraverseStmt(const_cast<Stmt *>(S));
  return Finder.found();
}

class InitVisitor : public RecursiveASTVisitor<InitVisitor> {
  const FunctionDecl *FD;
  ASTContext &AC;
  llvm::DenseSet<const ParmVarDecl *> ValidatedParams;
  llvm::DenseSet<const FieldDecl *> &UnvalidatedFields;

public:
  InitVisitor(const FunctionDecl *FD, ASTContext &AC,
              llvm::DenseSet<const FieldDecl *> &UnvalidatedFields)
      : FD(FD), AC(AC), UnvalidatedFields(UnvalidatedFields) {}

  bool VisitIfStmt(IfStmt *IS) {
    for (const ParmVarDecl *P : FD->parameters()) {
      bool ImpliesZero = false;
      if (conditionChecksParamZero(IS->getCond(), P, ImpliesZero)) {
        bool ThenAborts = containsReturnOrAbort(IS->getThen(), AC);
        bool ElseAborts = IS->getElse() && containsReturnOrAbort(IS->getElse(), AC);

        if ((ImpliesZero && ThenAborts) || (!ImpliesZero && ElseAborts)) {
          ValidatedParams.insert(P);
        }
      }
    }
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Assign)
      return true;

    const Expr *LHS = stripExpr(BO->getLHS());
    const Expr *RHS = stripExpr(BO->getRHS());
    if (!LHS || !RHS)
      return true;

    const auto *ME = dyn_cast<MemberExpr>(LHS);
    if (!ME)
      return true;

    const auto *F = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!F)
      return true;

    const auto *DRE = dyn_cast<DeclRefExpr>(RHS);
    if (!DRE)
      return true;

    const auto *P = dyn_cast<ParmVarDecl>(DRE->getDecl());
    if (!P)
      return true;

    if (P->getDeclContext() != FD)
      return true;

    if (ValidatedParams.contains(P))
      return true;

    UnvalidatedFields.insert(F);
    return true;
  }
};

class DivisionVisitor : public RecursiveASTVisitor<DivisionVisitor> {
  ASTContext &AC;
  llvm::SmallVectorImpl<UnsafeDivision> &UnsafeDivisions;
  llvm::SmallVector<IfStmt *, 8> IfStack;

public:
  DivisionVisitor(ASTContext &AC,
                  llvm::SmallVectorImpl<UnsafeDivision> &UnsafeDivisions)
      : AC(AC), UnsafeDivisions(UnsafeDivisions) {}

  bool TraverseIfStmt(IfStmt *IS) {
    IfStack.push_back(IS);
    bool Res = RecursiveASTVisitor<DivisionVisitor>::TraverseIfStmt(IS);
    IfStack.pop_back();
    return Res;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Div)
      return true;

    const Expr *RHS = stripExpr(BO->getRHS());
    if (!RHS)
      return true;

    const auto *ME = dyn_cast<MemberExpr>(RHS);
    if (!ME)
      return true;

    const auto *F = dyn_cast<FieldDecl>(ME->getMemberDecl());
    if (!F)
      return true;

    if (IfStack.empty())
      return true;

    IfStmt *IS = IfStack.back();

    // The enclosing if must contain an error_setter call in one of its branches.
    if (!containsErrorSetter(IS->getThen(), AC) &&
        !containsErrorSetter(IS->getElse(), AC))
      return true;

    // If the condition already guards this field against zero, it is safe.
    if (isNonZeroGuard(IS->getCond(), F))
      return true;

    UnsafeDivisions.push_back({F, BO->getOperatorLoc()});
    return true;
  }
};

class SAGenTestChecker
    : public Checker<check::ASTCodeBody, check::EndAnalysis> {
  mutable std::unique_ptr<BugType> BT;
  mutable llvm::DenseSet<const FieldDecl *> UnvalidatedFields;
  mutable llvm::SmallVector<UnsafeDivision, 8> UnsafeDivisions;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Division by Unvalidated Configuration Value",
                       "Logic Error")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                        ExprEngine &Eng) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->getBody())
    return;

  ASTContext &AC = Mgr.getASTContext();

  if (knighter::declIsRole(FD, "init")) {
    InitVisitor IV(FD, AC, UnvalidatedFields);
    IV.TraverseStmt(FD->getBody());
  }

  DivisionVisitor DV(AC, UnsafeDivisions);
  DV.TraverseStmt(FD->getBody());
}

void SAGenTestChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                                        ExprEngine &Eng) const {
  for (const UnsafeDivision &UD : UnsafeDivisions) {
    if (UnvalidatedFields.contains(UD.Field)) {
      auto Report = std::make_unique<BasicBugReport>(
          *BT, "Division by unvalidated configuration value (may be zero)",
          PathDiagnosticLocation(UD.Loc, BR.getSourceManager()));
      BR.emitReport(std::move(Report));
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects division by an unvalidated configuration value that may be zero",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "init": {"names": ["xmlCtxtSetMaxAmplification"], "description": "configuration setter that stores a caller-supplied value into an object field"},
  "error_setter": {"names": ["xmlFatalErrMsg"], "description": "printf-style function that records or reports an error condition"},
  "aborting_assert": {"names": ["aborting_assert"], "description": "macro or function that aborts execution (or returns) when its condition is false, so the guarded value is considered validated"}
}
*/
