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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/SmallPtrSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper: Check if a function has a zero guard for parameter P.
static bool hasZeroGuard(const FunctionDecl *D, const ParmVarDecl *P) {
  if (!D->hasBody()) return false;
  Stmt *Body = D->getBody();
  class Visitor : public RecursiveASTVisitor<Visitor> {
    const ParmVarDecl *P;
  public:
    bool Found = false;
    Visitor(const ParmVarDecl *P) : P(P) {}
    bool VisitIfStmt(IfStmt *IS) {
      if (Found) return true;
      const Expr *Cond = IS->getCond();
      if (!Cond) return true;
      Cond = Cond->IgnoreParenImpCasts();
      if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
        BinaryOperator::Opcode Op = BO->getOpcode();
        if (Op == BO_EQ || Op == BO_LE || Op == BO_LT) {
          const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
          const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
          auto isP = [&](const Expr *E) -> bool {
            if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
              return DRE->getDecl() == P;
            }
            return false;
          };
          auto isZero = [&](const Expr *E) -> bool {
            if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
              return IL->getValue() == 0;
            }
            return false;
          };
          auto isOne = [&](const Expr *E) -> bool {
            if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
              return IL->getValue() == 1;
            }
            return false;
          };
          bool match = false;
          if (isP(LHS) && isZero(RHS)) {
            if (Op == BO_EQ || Op == BO_LE) match = true;
          } else if (isZero(LHS) && isP(RHS)) {
            if (Op == BO_EQ || Op == BO_GE) match = true;
          } else if (isP(LHS) && isOne(RHS)) {
            if (Op == BO_LT) match = true;
          } else if (isOne(LHS) && isP(RHS)) {
            if (Op == BO_GT) match = true;
          }
          if (match) {
            const Stmt *Then = IS->getThen();
            if (Then) {
              class ReturnFinder : public RecursiveASTVisitor<ReturnFinder> {
              public:
                bool FoundReturn = false;
                bool VisitReturnStmt(ReturnStmt *RS) {
                  FoundReturn = true;
                  return false;
                }
              };
              ReturnFinder RF;
              RF.TraverseStmt(const_cast<Stmt*>(Then));
              if (RF.FoundReturn) {
                Found = true;
                return false;
              }
            }
          }
        }
      }
      return true;
    }
  };
  Visitor V(P);
  V.TraverseStmt(Body);
  return V.Found;
}

// Helper: Collect fields assigned from parameter P.
static void collectAssignedFields(const FunctionDecl *D, const ParmVarDecl *P,
                                  llvm::SmallVectorImpl<const FieldDecl *> &Fields) {
  if (!D->hasBody()) return;
  Stmt *Body = D->getBody();
  class Visitor : public RecursiveASTVisitor<Visitor> {
    const ParmVarDecl *P;
    llvm::SmallVectorImpl<const FieldDecl *> &Fields;
  public:
    Visitor(const ParmVarDecl *P, llvm::SmallVectorImpl<const FieldDecl *> &Fields)
        : P(P), Fields(Fields) {}
    bool VisitBinaryOperator(BinaryOperator *BO) {
      if (BO->getOpcode() != BO_Assign) return true;
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const MemberExpr *ME = dyn_cast<MemberExpr>(LHS);
      if (!ME) return true;
      const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
      if (!FD) return true;
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      class DeclRefFinder : public RecursiveASTVisitor<DeclRefFinder> {
        const ParmVarDecl *P;
      public:
        bool Found = false;
        DeclRefFinder(const ParmVarDecl *P) : P(P) {}
        bool VisitDeclRefExpr(DeclRefExpr *DRE) {
          if (DRE->getDecl() == P) {
            Found = true;
            return false;
          }
          return true;
        }
      };
      DeclRefFinder Finder(P);
      Finder.TraverseStmt(const_cast<Expr*>(RHS));
      if (Finder.Found) {
        Fields.push_back(FD);
      }
      return true;
    }
  };
  Visitor V(P, Fields);
  V.TraverseStmt(Body);
}

// Helper: Check if an expression contains a nonzero guard for field FD.
static bool hasNonZeroGuard(const Expr *E, const FieldDecl *FD) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      return hasNonZeroGuard(BO->getLHS(), FD) || hasNonZeroGuard(BO->getRHS(), FD);
    }
    if (BO->getOpcode() == BO_GT || BO->getOpcode() == BO_NE || BO->getOpcode() == BO_LT) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      auto isFD = [&](const Expr *E) -> bool {
        if (const MemberExpr *ME = dyn_cast<MemberExpr>(E)) {
          return ME->getMemberDecl() == FD;
        }
        return false;
      };
      auto isZero = [&](const Expr *E) -> bool {
        if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
          return IL->getValue() == 0;
        }
        return false;
      };
      if (isFD(LHS) && isZero(RHS)) {
        if (BO->getOpcode() == BO_GT || BO->getOpcode() == BO_NE) return true;
      }
      if (isZero(LHS) && isFD(RHS)) {
        if (BO->getOpcode() == BO_LT || BO->getOpcode() == BO_NE) return true;
      }
    }
  }
  return false;
}

class SAGenTestChecker : public Checker<check::ASTDecl<FunctionDecl>, check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;
  mutable llvm::SmallPtrSet<const FieldDecl *, 8> UnvalidatedConfigFields;

public:
  SAGenTestChecker() : BT(new BugType(this, "Division by unvalidated config value", "Logic Error")) {}

  void checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
};

void SAGenTestChecker::checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (!knighter::declIsRole(D, "init")) return;
  for (const ParmVarDecl *P : D->parameters()) {
    QualType Ty = P->getType();
    if (!Ty->isIntegerType()) continue;
    if (hasZeroGuard(D, P)) continue;
    llvm::SmallVector<const FieldDecl *, 4> Fields;
    collectAssignedFields(D, P, Fields);
    for (const FieldDecl *FD : Fields) {
      UnvalidatedConfigFields.insert(FD);
    }
  }
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const {
  if (BO->getOpcode() != BO_Div) return;
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  const MemberExpr *ME = dyn_cast<MemberExpr>(RHS);
  if (!ME) return;
  const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD) return;
  if (UnvalidatedConfigFields.find(FD) == UnvalidatedConfigFields.end()) return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(BO, C);
  if (IS) {
    const Expr *Cond = IS->getCond();
    if (hasNonZeroGuard(Cond, FD)) return;
  }

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;
  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Division by potentially zero value set by init API", N);
  report->addRange(BO->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects division by a value set by an init API without zero validation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "init": {"names": ["xmlCtxtSetMaxAmplification"], "description": "setter that stores a caller-supplied numeric configuration value into a context object"}
}
*/
