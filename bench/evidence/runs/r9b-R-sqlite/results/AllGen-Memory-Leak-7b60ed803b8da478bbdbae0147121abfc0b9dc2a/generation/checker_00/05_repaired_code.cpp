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

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Collect all CallExpr nodes in a statement subtree.
static void collectCallExprs(const Stmt *S,
                             llvm::SmallVectorImpl<const CallExpr *> &Calls) {
  if (!S)
    return;

  if (const auto *CE = dyn_cast<CallExpr>(S))
    Calls.push_back(CE);

  for (const Stmt *Child : S->children())
    collectCallExprs(Child, Calls);
}

// If E is a reference to a local variable, return its VarDecl.
static const VarDecl *declRefVar(const Expr *E) {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    return dyn_cast<VarDecl>(DRE->getDecl());

  return nullptr;
}

// Does the statement subtree reference the given variable?
static bool usesVar(const Stmt *S, const VarDecl *VD) {
  if (!S || !VD)
    return false;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (DRE->getDecl() == VD)
      return true;
  }

  for (const Stmt *Child : S->children()) {
    if (usesVar(Child, VD))
      return true;
  }

  return false;
}

// Does the expression directly call an API with the given role?
static bool exprIsRole(const Expr *E, StringRef Role, ASTContext &Ctx) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  if (const auto *CE = dyn_cast<CallExpr>(E))
    return knighter::callExprIsRole(CE, Role, Ctx);

  return false;
}

// Is E a call to an allocator/duplicator/null-on-failure API?
static bool isOwnedSourceCall(const Expr *E, ASTContext &Ctx) {
  return exprIsRole(E, "allocator", Ctx) ||
         exprIsRole(E, "duplicator", Ctx) ||
         exprIsRole(E, "null_on_failure", Ctx);
}

static bool isVarRefTo(const Expr *E, const VarDecl *VD) {
  if (!E || !VD)
    return false;

  E = E->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  return DRE && DRE->getDecl() == VD;
}

static bool isNullPointerConstantExpr(const Expr *E, ASTContext &Ctx) {
  return E && E->isNullPointerConstant(Ctx, Expr::NPC_ValueDependentIsNull);
}

// Is this a non-null test of VD, e.g. "VD", "VD != NULL", "NULL != VD"?
static bool isNonNullTestOfVar(const Expr *E, const VarDecl *VD,
                               ASTContext &Ctx) {
  if (!E || !VD)
    return false;

  E = E->IgnoreParenImpCasts();

  if (isVarRefTo(E, VD))
    return true;

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_NE) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

      if ((isVarRefTo(L, VD) && isNullPointerConstantExpr(R, Ctx)) ||
          (isVarRefTo(R, VD) && isNullPointerConstantExpr(L, Ctx)))
        return true;
    }
  }

  return false;
}

// Is this a null test of VD, e.g. "!VD", "VD == NULL", "NULL == VD"?
static bool isNullTestOfVar(const Expr *E, const VarDecl *VD,
                            ASTContext &Ctx) {
  if (!E || !VD)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (isVarRefTo(Sub, VD))
        return true;
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

      if ((isVarRefTo(L, VD) && isNullPointerConstantExpr(R, Ctx)) ||
          (isVarRefTo(R, VD) && isNullPointerConstantExpr(L, Ctx)))
        return true;
    }
  }

  return false;
}

static void flattenAnd(const Expr *E, llvm::SmallVectorImpl<const Expr *> &Ops) {
  if (!E)
    return;

  E = E->IgnoreParenImpCasts();
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      flattenAnd(BO->getLHS(), Ops);
      flattenAnd(BO->getRHS(), Ops);
      return;
    }
  }

  Ops.push_back(E);
}

// True if the condition is a conjunction that checks VD non-null and also
// contains at least one other operand not merely being a null test of VD.
static bool isNonNullAndOtherGuard(const Stmt *Condition, const VarDecl *VD,
                                   ASTContext &Ctx) {
  const auto *Cond = dyn_cast<Expr>(Condition);
  if (!Cond || !VD)
    return false;

  llvm::SmallVector<const Expr *, 4> Ops;
  flattenAnd(Cond, Ops);

  bool HasNonNull = false;
  bool HasOther = false;

  for (const Expr *Op : Ops) {
    if (isNonNullTestOfVar(Op, VD, Ctx)) {
      HasNonNull = true;
    } else if (!isNullTestOfVar(Op, VD, Ctx)) {
      HasOther = true;
    }
  }

  return HasNonNull && HasOther;
}

// True if Else contains a deallocator call that receives VD as an argument.
static bool elseHandlesDealloc(const Stmt *Else, const VarDecl *VD,
                               ASTContext &Ctx) {
  if (!Else || !VD)
    return false;

  llvm::SmallVector<const CallExpr *, 8> Calls;
  collectCallExprs(Else, Calls);

  for (const CallExpr *CE : Calls) {
    if (!knighter::callExprIsRole(CE, "deallocator", Ctx))
      continue;

    for (unsigned I = 0; I < CE->getNumArgs(); ++I) {
      if (usesVar(CE->getArg(I), VD))
        return true;
    }
  }

  return false;
}

// Scan the enclosing function for an assignment/initialization to VD whose RHS
// is an owned-source call and which occurs before the relevant IfStmt.
static bool isOwnedSource(const VarDecl *VD, const IfStmt *IS, ASTContext &Ctx,
                          const SourceManager &SM, const FunctionDecl *FD) {
  if (!VD || !IS || !FD || !FD->hasBody())
    return false;

  struct Scanner {
    const VarDecl *VD;
    SourceLocation BeforeLoc;
    ASTContext &Ctx;
    const SourceManager &SM;
    bool Found = false;

    bool scan(const Stmt *S) {
      if (!S || Found)
        return Found;

      if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *D : DS->decls()) {
          const auto *Decl = dyn_cast<VarDecl>(D);
          if (Decl != VD || !Decl->hasInit())
            continue;

          SourceLocation Loc = Decl->getLocation();
          if (Loc.isValid() && SM.isBeforeInTranslationUnit(Loc, BeforeLoc) &&
              isOwnedSourceCall(Decl->getInit(), Ctx)) {
            Found = true;
            return true;
          }
        }
      }

      if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->getOpcode() == BO_Assign) {
          const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
          if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
            if (DRE->getDecl() == VD) {
              SourceLocation Loc = BO->getOperatorLoc();
              if (Loc.isValid() &&
                  SM.isBeforeInTranslationUnit(Loc, BeforeLoc) &&
                  isOwnedSourceCall(BO->getRHS(), Ctx)) {
                Found = true;
                return true;
              }
            }
          }
        }
      }

      for (const Stmt *Child : S->children()) {
        if (scan(Child))
          return true;
      }

      return false;
    }
  };

  Scanner S{VD, IS->getBeginLoc(), Ctx, SM};
  return S.scan(FD->getBody());
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory leak", "Potential memory leak")) {}

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

  const Stmt *Then = IS->getThen();
  const Stmt *Else = IS->getElse();
  if (!Then)
    return;

  ASTContext &Ctx = C.getASTContext();
  const SourceManager &SM = C.getSourceManager();

  const AnalysisDeclContext *ADC = C.getCurrentAnalysisDeclContext();
  if (!ADC)
    return;

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(ADC->getDecl());
  if (!FD)
    return;

  llvm::SmallVector<const CallExpr *, 8> Calls;
  collectCallExprs(Then, Calls);

  for (const CallExpr *CI : Calls) {
    if (!CI)
      continue;

    if (!knighter::callExprIsRole(CI, "container_insert", Ctx))
      continue;

    for (unsigned I = 0; I < CI->getNumArgs(); ++I) {
      const Expr *Arg = CI->getArg(I);
      const VarDecl *VD = declRefVar(Arg);
      if (!VD)
        continue;

      if (!usesVar(Condition, VD))
        continue;

      if (!isOwnedSource(VD, IS, Ctx, SM, FD))
        continue;

      if (!isNonNullAndOtherGuard(Condition, VD, Ctx))
        continue;

      // If the else branch already deallocates the owned pointer, the leak is
      // handled on the non-transfer path.
      if (elseHandlesDealloc(Else, VD, Ctx))
        continue;

      PathDiagnosticLocation Loc =
          PathDiagnosticLocation::createBegin(CI, SM, C.getLocationContext());
      C.emitReport(std::make_unique<BasicBugReport>(
          *BT,
          "Potential memory leak: allocated pointer is not deallocated when "
          "ownership transfer is skipped",
          Loc));
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memory leaks when an allocated pointer is conditionally "
      "transferred into a container and the non-transfer path lacks a "
      "deallocator",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {"names": ["sqlite3SrcListAppendFromTerm"], "description": "allocates a new object and returns a pointer to it, or NULL on failure"},
  "duplicator": {"names": ["sqlite3SrcListDup"], "description": "creates a duplicate of an object and returns a pointer to it, or NULL on failure"},
  "container_insert": {"names": ["sqlite3SrcListAppendList"], "description": "transfers ownership of an object into a container or list; on success the container takes responsibility for freeing it"},
  "deallocator": {"names": ["sqlite3SrcListDelete"], "description": "frees an object or memory; the pointer must not be used afterwards"},
  "null_on_failure": {"names": ["sqlite3SrcListDup", "sqlite3SrcListAppendFromTerm"], "description": "may return NULL to indicate failure, so callers must check the result before use"}
}
*/
