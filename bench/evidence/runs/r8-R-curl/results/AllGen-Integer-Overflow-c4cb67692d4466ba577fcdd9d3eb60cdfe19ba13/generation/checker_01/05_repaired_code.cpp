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
#include "llvm/ADT/StringRef.h"

#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool isNarrowIntegerType(const VarDecl *VD, ASTContext &Ctx) {
  if (!VD)
    return false;

  QualType Ty = VD->getType();
  if (!Ty->isIntegerType())
    return false;

  return Ctx.getTypeSize(Ty) < Ctx.getTypeSize(Ctx.getSizeType());
}

static bool exprReferencesDecl(const Expr *E, const VarDecl *Target) {
  if (!E || !Target)
    return false;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts())) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (VD == Target)
        return true;
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *ChildExpr = dyn_cast<Expr>(Child)) {
      if (exprReferencesDecl(ChildExpr, Target))
        return true;
    }
  }
  return false;
}

static const VarDecl *findRoleVarInExpr(const Expr *E, llvm::StringRef Role) {
  if (!E)
    return nullptr;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts())) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (knighter::declIsRole(VD, Role))
        return VD;
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *ChildExpr = dyn_cast<Expr>(Child)) {
      if (const VarDecl *VD = findRoleVarInExpr(ChildExpr, Role))
        return VD;
    }
  }
  return nullptr;
}

static bool findAddCombiningRoleVars(const Expr *Cond, CheckerContext &C,
                                     const VarDecl *&LenVD,
                                     const VarDecl *&OffVD) {
  if (!Cond)
    return false;

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_Add) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();

      const VarDecl *LOff = findRoleVarInExpr(LHS, "offset_holder");
      const VarDecl *RLen = findRoleVarInExpr(RHS, "length_holder");
      if (LOff && RLen) {
        LenVD = RLen;
        OffVD = LOff;
        return true;
      }

      const VarDecl *LLen = findRoleVarInExpr(LHS, "length_holder");
      const VarDecl *ROff = findRoleVarInExpr(RHS, "offset_holder");
      if (LLen && ROff) {
        LenVD = LLen;
        OffVD = ROff;
        return true;
      }
    }
  }

  for (const Stmt *Child : Cond->children()) {
    if (const auto *ChildExpr = dyn_cast<Expr>(Child)) {
      if (findAddCombiningRoleVars(ChildExpr, C, LenVD, OffVD))
        return true;
    }
  }
  return false;
}

static const CallExpr *findBufferAccessCall(const Stmt *Branch,
                                            const VarDecl *LenVD,
                                            const VarDecl *OffVD,
                                            CheckerContext &C) {
  if (!Branch)
    return nullptr;

  if (const auto *CE = dyn_cast<CallExpr>(Branch)) {
    llvm::StringRef CalleeName;
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      CalleeName = FD->getName();
    } else if (const Decl *D = CE->getCalleeDecl()) {
      if (const auto *ND = dyn_cast<NamedDecl>(D))
        CalleeName = ND->getName();
    }

    bool IsBufferAccess = false;
    if (!CalleeName.empty()) {
      IsBufferAccess = knighter::isRole("buffer_access", CalleeName);
    } else {
      for (const std::string &Name : knighter::roleNames("buffer_access")) {
        if (ExprHasName(CE->getCallee(), Name, C)) {
          IsBufferAccess = true;
          break;
        }
      }
    }

    if (IsBufferAccess) {
      bool RefLen = false;
      bool RefOff = false;
      for (unsigned I = 0, E = CE->getNumArgs(); I != E; ++I) {
        const Expr *Arg = CE->getArg(I);
        if (exprReferencesDecl(Arg, LenVD))
          RefLen = true;
        if (exprReferencesDecl(Arg, OffVD))
          RefOff = true;
      }
      if (RefLen && RefOff)
        return CE;
    }
  }

  for (const Stmt *Child : Branch->children()) {
    if (const CallExpr *CE = findBufferAccessCall(Child, LenVD, OffVD, C))
      return CE;
  }
  return nullptr;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Narrow integer in bounds check",
                       "Integer overflow")) {}

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

  const Expr *Cond = IS->getCond();
  if (!Cond)
    return;
  Cond = Cond->IgnoreParenImpCasts();

  const auto *RelBO = dyn_cast<BinaryOperator>(Cond);
  if (!RelBO)
    return;

  const BinaryOperator::Opcode Op = RelBO->getOpcode();
  if (Op != BO_GT && Op != BO_GE && Op != BO_LT && Op != BO_LE)
    return;

  const VarDecl *LenVD = nullptr;
  const VarDecl *OffVD = nullptr;
  if (!findAddCombiningRoleVars(Cond, C, LenVD, OffVD))
    return;

  if (!LenVD || !OffVD)
    return;

  ASTContext &Ctx = C.getASTContext();
  if (!isNarrowIntegerType(LenVD, Ctx) || !isNarrowIntegerType(OffVD, Ctx))
    return;

  const Stmt *SafeBranch = nullptr;
  if (Op == BO_GT || Op == BO_GE)
    SafeBranch = IS->getElse();
  else
    SafeBranch = IS->getThen();

  if (!SafeBranch)
    return;

  const CallExpr *BufferCall = findBufferAccessCall(SafeBranch, LenVD, OffVD, C);
  if (!BufferCall)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Narrow integer in bounds check may overflow", N);
  Report->addRange(Cond->getSourceRange());
  Report->addRange(BufferCall->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects narrow integer overflow in bounds checks followed by buffer access",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "length_holder": {"names": ["len"], "description": "variable holding a length used in a bounds check"},
  "offset_holder": {"names": ["off"], "description": "variable holding an offset used in a bounds check"},
  "buffer_access": {"names": ["Curl_client_write"], "description": "function/macro that accesses a buffer using a length and offset"}
}
*/
