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

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/ADT/SmallVector.h"
#include "knighter/roles.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool isSmallInteger(QualType QT, ASTContext &Ctx) {
  if (!QT->isIntegerType())
    return false;
  if (QT->isBooleanType())
    return false;
  unsigned Width = Ctx.getIntWidth(QT);
  return Width > 0 && Width <= 32;
}

static bool containsBinaryOpcode(const Expr *E, BinaryOperatorKind Op) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == Op)
      return true;
  }
  for (const Stmt *Child : E->children()) {
    if (const Expr *CE = dyn_cast<Expr>(Child)) {
      if (containsBinaryOpcode(CE, Op))
        return true;
    }
  }
  return false;
}

static bool hasNonConstantIntegerOperand(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (isa<IntegerLiteral>(E) || isa<CharacterLiteral>(E) || isa<GNUNullExpr>(E))
    return false;
  if (isa<DeclRefExpr>(E) || isa<MemberExpr>(E) || isa<ArraySubscriptExpr>(E) ||
      isa<CallExpr>(E)) {
    return E->getType()->isIntegerType();
  }
  for (const Stmt *Child : E->children()) {
    if (const Expr *CE = dyn_cast<Expr>(Child)) {
      if (hasNonConstantIntegerOperand(CE))
        return true;
    }
  }
  return false;
}

static bool isOverflowProneCountExpr(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Div)
    return false;
  const Expr *Numerator = BO->getLHS()->IgnoreParenImpCasts();
  return containsBinaryOpcode(Numerator, BO_Add) &&
         containsBinaryOpcode(Numerator, BO_Sub) &&
         hasNonConstantIntegerOperand(Numerator);
}

static bool exprReferencesDecl(const Expr *E, const VarDecl *VD) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *FoundVD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (FoundVD == VD)
        return true;
    }
  }
  for (const Stmt *Child : E->children()) {
    if (const Expr *CE = dyn_cast<Expr>(Child)) {
      if (exprReferencesDecl(CE, VD))
        return true;
    }
  }
  return false;
}

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow", "Integer Overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  ASTContext &Ctx = Mgr.getASTContext();
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  class VarCollector : public RecursiveASTVisitor<VarCollector> {
  public:
    ASTContext &Ctx;
    llvm::SmallVectorImpl<const VarDecl *> &Candidates;
    VarCollector(ASTContext &Ctx,
                 llvm::SmallVectorImpl<const VarDecl *> &Candidates)
        : Ctx(Ctx), Candidates(Candidates) {}

    bool VisitVarDecl(VarDecl *VD) {
      if (!VD->hasInit())
        return true;
      if (!isSmallInteger(VD->getType(), Ctx))
        return true;
      if (!isOverflowProneCountExpr(VD->getInit()))
        return true;
      Candidates.push_back(VD);
      return true;
    }
  };

  llvm::SmallVector<const VarDecl *, 8> Candidates;
  VarCollector VC(Ctx, Candidates);
  VC.TraverseStmt(const_cast<Stmt *>(Body));

  for (const VarDecl *VD : Candidates) {
    class UseFinder : public RecursiveASTVisitor<UseFinder> {
    public:
      ASTContext &Ctx;
      const VarDecl *Target;
      bool FoundRealloc = false;
      bool FoundInit = false;

      UseFinder(ASTContext &Ctx, const VarDecl *VD)
          : Ctx(Ctx), Target(VD) {}

      bool VisitCallExpr(CallExpr *CE) {
        if (!FoundRealloc &&
            knighter::callExprIsRole(CE, "reallocator", Ctx)) {
          if (CE->getNumArgs() >= 2 &&
              exprReferencesDecl(CE->getArg(1), Target)) {
            FoundRealloc = true;
          }
        }
        if (!FoundInit && knighter::callExprIsRole(CE, "init", Ctx)) {
          if (CE->getNumArgs() >= 3 &&
              exprReferencesDecl(CE->getArg(2), Target)) {
            FoundInit = true;
          }
        }
        return true;
      }
    };

    UseFinder UF(Ctx, VD);
    UF.TraverseStmt(const_cast<Stmt *>(Body));

    if (UF.FoundRealloc && UF.FoundInit) {
      PathDiagnosticLocation L =
          PathDiagnosticLocation::create(VD, BR.getSourceManager());
      auto Report = std::make_unique<BasicBugReport>(
          *BT, "32-bit size computation may overflow before allocation", L);
      Report->addRange(VD->getSourceRange());
      BR.emitReport(std::move(Report));
    }
  }
}

} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects 32-bit size computations that may overflow before allocation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "reallocator": {"names": ["sqlite3Realloc"], "description": "reallocates a memory block; its size argument is the total requested byte count"},
  "length_of": {"names": ["sqlite3MallocSize"], "description": "returns the usable size in bytes of an allocated memory region"},
  "init": {"names": ["memset"], "description": "writes a byte value over a given number of bytes; its length argument must not exceed the destination buffer size"}
}
*/
