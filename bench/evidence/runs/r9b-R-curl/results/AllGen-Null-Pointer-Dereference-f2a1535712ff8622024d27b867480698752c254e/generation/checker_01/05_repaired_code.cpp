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

#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Returns the ParmVarDecl referenced by an expression, ignoring parens and
// implicit casts.
static const ParmVarDecl *getParamFromExpr(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const ParmVarDecl *P = dyn_cast<ParmVarDecl>(DRE->getDecl()))
      return P;
  }
  return nullptr;
}

// Returns true if E is a dereference of parameter P, i.e. `*P`.
static bool isDerefOfParam(const Expr *E, const ParmVarDecl *P) {
  if (!E || !P)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub))
        return DRE->getDecl() == P;
    }
  }
  return false;
}

// Returns true if S is an assignment whose LHS is a dereference of P.
static bool isAssignmentToParam(const Stmt *S, const ParmVarDecl *P) {
  if (!S || !P)
    return false;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign)
      return isDerefOfParam(BO->getLHS(), P);
  }

  if (const CompoundAssignOperator *CAO = dyn_cast<CompoundAssignOperator>(S))
    return isDerefOfParam(CAO->getLHS(), P);

  return false;
}

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

  // Cache for output-parameter indices of functions.  Used to avoid
  // recomputation and to break recursion cycles.
  mutable llvm::DenseMap<const FunctionDecl *, llvm::SmallVector<unsigned, 4>>
      OutputParamCache;
  mutable llvm::SmallPtrSet<const FunctionDecl *, 8> OutputParamInProgress;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Null output argument", "API misuse")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

private:
  void getOutputParamIndices(const FunctionDecl *FD,
                             llvm::SmallVectorImpl<unsigned> &Indices,
                             ASTContext &Ctx) const;

  bool hasDirectWrite(const Stmt *S, const ParmVarDecl *P) const;

  bool isForwardedToOutputWriter(const FunctionDecl *FD,
                                 const ParmVarDecl *P,
                                 ASTContext &Ctx) const;

  bool stmtHasForwardedOutput(const Stmt *S, const ParmVarDecl *P,
                              ASTContext &Ctx) const;

  bool isOutputUse(const Stmt *S, const ParmVarDecl *P,
                   ASTContext &Ctx) const;

  const Stmt *findFirstOutputUse(const FunctionDecl *FD,
                                 const ParmVarDecl *P,
                                 ASTContext &Ctx) const;

  bool hasValidNullGuard(const FunctionDecl *FD, const ParmVarDecl *P,
                         const Stmt *FirstUse, ASTContext &Ctx) const;

  bool isNullTest(const Expr *Cond, const ParmVarDecl *P, bool &IsNullTest,
                  ASTContext &Ctx) const;

  bool isStmtContained(const Stmt *Parent, const Stmt *Child) const;

  bool containsTerminatorOrAbort(const Stmt *S, ASTContext &Ctx) const;

  void collectIfStmts(const Stmt *S,
                      llvm::SmallVectorImpl<const IfStmt *> &Ifs) const;
};

void SAGenTestChecker::getOutputParamIndices(
    const FunctionDecl *FD, llvm::SmallVectorImpl<unsigned> &Indices,
    ASTContext &Ctx) const {
  if (!FD)
    return;

  auto It = OutputParamCache.find(FD);
  if (It != OutputParamCache.end()) {
    Indices.append(It->second.begin(), It->second.end());
    return;
  }

  if (OutputParamInProgress.count(FD))
    return; // recursion cycle

  OutputParamInProgress.insert(FD);

  const Stmt *Body = FD->getBody();
  if (!Body) {
    OutputParamInProgress.erase(FD);
    return;
  }

  llvm::SmallVector<unsigned, 4> Result;
  for (unsigned i = 0; i < FD->getNumParams(); ++i) {
    const ParmVarDecl *P = FD->getParamDecl(i);
    bool IsOut = hasDirectWrite(Body, P);
    if (!IsOut)
      IsOut = isForwardedToOutputWriter(FD, P, Ctx);
    if (IsOut)
      Result.push_back(i);
  }

  OutputParamCache[FD] = Result;
  OutputParamInProgress.erase(FD);
  Indices.append(Result.begin(), Result.end());
}

bool SAGenTestChecker::hasDirectWrite(const Stmt *S,
                                      const ParmVarDecl *P) const {
  if (!S)
    return false;
  if (isAssignmentToParam(S, P))
    return true;
  for (const Stmt *Child : S->children()) {
    if (hasDirectWrite(Child, P))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isForwardedToOutputWriter(
    const FunctionDecl *FD, const ParmVarDecl *P, ASTContext &Ctx) const {
  const Stmt *Body = FD->getBody();
  if (!Body)
    return false;
  return stmtHasForwardedOutput(Body, P, Ctx);
}

bool SAGenTestChecker::stmtHasForwardedOutput(const Stmt *S,
                                              const ParmVarDecl *P,
                                              ASTContext &Ctx) const {
  if (!S)
    return false;

  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (knighter::callExprIsRole(CE, "output_writer", Ctx)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (Callee) {
        llvm::SmallVector<unsigned, 4> CalleeOut;
        getOutputParamIndices(Callee, CalleeOut, Ctx);
        for (unsigned idx : CalleeOut) {
          if (idx < CE->getNumArgs()) {
            const Expr *Arg = CE->getArg(idx)->IgnoreParenImpCasts();
            if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Arg)) {
              if (DRE->getDecl() == P)
                return true;
            }
          }
        }
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (stmtHasForwardedOutput(Child, P, Ctx))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isOutputUse(const Stmt *S, const ParmVarDecl *P,
                                   ASTContext &Ctx) const {
  if (!S)
    return false;

  if (isAssignmentToParam(S, P))
    return true;

  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (knighter::callExprIsRole(CE, "output_writer", Ctx)) {
      const FunctionDecl *Callee = CE->getDirectCallee();
      if (Callee) {
        llvm::SmallVector<unsigned, 4> CalleeOut;
        getOutputParamIndices(Callee, CalleeOut, Ctx);
        for (unsigned idx : CalleeOut) {
          if (idx < CE->getNumArgs()) {
            const Expr *Arg = CE->getArg(idx)->IgnoreParenImpCasts();
            if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Arg)) {
              if (DRE->getDecl() == P)
                return true;
            }
          }
        }
      }
    }
  }

  return false;
}

const Stmt *SAGenTestChecker::findFirstOutputUse(const FunctionDecl *FD,
                                                 const ParmVarDecl *P,
                                                 ASTContext &Ctx) const {
  const Stmt *Body = FD->getBody();
  if (!Body)
    return nullptr;

  const Stmt *Best = nullptr;
  SourceManager &SM = Ctx.getSourceManager();

  auto Visit = [&](auto &&Self, const Stmt *S) -> void {
    if (!S)
      return;

    if (isOutputUse(S, P, Ctx)) {
      if (!Best ||
          SM.isBeforeInTranslationUnit(S->getBeginLoc(), Best->getBeginLoc())) {
        Best = S;
      }
    }

    for (const Stmt *Child : S->children())
      Self(Self, Child);
  };

  Visit(Visit, Body);
  return Best;
}

bool SAGenTestChecker::isNullTest(const Expr *Cond, const ParmVarDecl *P,
                                  bool &IsNullTest, ASTContext &Ctx) const {
  if (!Cond || !P)
    return false;

  Cond = Cond->IgnoreParenImpCasts();

  // if (!P)
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      if (getParamFromExpr(UO->getSubExpr()) == P) {
        IsNullTest = true;
        return true;
      }
    }
  }

  // if (P)
  if (getParamFromExpr(Cond) == P) {
    IsNullTest = false;
    return true;
  }

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();
      const ParmVarDecl *LP = getParamFromExpr(LHS);
      const ParmVarDecl *RP = getParamFromExpr(RHS);

      bool LNull = LHS->IgnoreParenImpCasts()->isNullPointerConstant(
          Ctx, Expr::NPC_ValueDependentIsNull);
      bool RNull = RHS->IgnoreParenImpCasts()->isNullPointerConstant(
          Ctx, Expr::NPC_ValueDependentIsNull);

      if (LP == P && RNull) {
        IsNullTest = (BO->getOpcode() == BO_EQ);
        return true;
      }
      if (RP == P && LNull) {
        IsNullTest = (BO->getOpcode() == BO_EQ);
        return true;
      }
    }
  }

  return false;
}

bool SAGenTestChecker::isStmtContained(const Stmt *Parent,
                                       const Stmt *Child) const {
  if (!Parent || !Child)
    return false;
  if (Parent == Child)
    return true;
  for (const Stmt *C : Parent->children()) {
    if (isStmtContained(C, Child))
      return true;
  }
  return false;
}

bool SAGenTestChecker::containsTerminatorOrAbort(const Stmt *S,
                                                 ASTContext &Ctx) const {
  if (!S)
    return false;

  if (isa<ReturnStmt>(S) || isa<GotoStmt>(S) || isa<BreakStmt>(S) ||
      isa<ContinueStmt>(S))
    return true;

  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (knighter::callExprIsRole(CE, "aborting_assert", Ctx))
      return true;
  }

  for (const Stmt *Child : S->children()) {
    if (containsTerminatorOrAbort(Child, Ctx))
      return true;
  }
  return false;
}

void SAGenTestChecker::collectIfStmts(
    const Stmt *S, llvm::SmallVectorImpl<const IfStmt *> &Ifs) const {
  if (!S)
    return;
  if (const IfStmt *IS = dyn_cast<IfStmt>(S))
    Ifs.push_back(IS);
  for (const Stmt *Child : S->children())
    collectIfStmts(Child, Ifs);
}

bool SAGenTestChecker::hasValidNullGuard(const FunctionDecl *FD,
                                         const ParmVarDecl *P,
                                         const Stmt *FirstUse,
                                         ASTContext &Ctx) const {
  const Stmt *Body = FD->getBody();
  if (!Body || !FirstUse)
    return false;

  llvm::SmallVector<const IfStmt *, 8> Ifs;
  collectIfStmts(Body, Ifs);

  SourceManager &SM = Ctx.getSourceManager();

  for (const IfStmt *IS : Ifs) {
    bool IsNullTest = false;
    if (!isNullTest(IS->getCond(), P, IsNullTest, Ctx))
      continue;

    if (!IsNullTest) {
      // Non-null test: the first use must be inside the then-branch.
      if (IS->getThen() && isStmtContained(IS->getThen(), FirstUse))
        return true;
    } else {
      // Null test: valid if the first use is inside the else-branch, or if
      // the if-statement appears before the use and its then-branch
      // terminates (return/goto/break/continue/abort).
      if (IS->getElse() && isStmtContained(IS->getElse(), FirstUse))
        return true;

      if (SM.isBeforeInTranslationUnit(IS->getBeginLoc(),
                                       FirstUse->getBeginLoc())) {
        if (IS->getThen() && containsTerminatorOrAbort(IS->getThen(), Ctx))
          return true;
      }
    }
  }

  return false;
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D,
                                        AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  if (!FD->getBody())
    return;

  if (!knighter::declIsRole(FD, "out_parameter_user"))
    return;

  ASTContext &Ctx = FD->getASTContext();

  llvm::SmallVector<unsigned, 4> OutIndices;
  getOutputParamIndices(FD, OutIndices, Ctx);

  for (unsigned idx : OutIndices) {
    if (idx >= FD->getNumParams())
      continue;

    const ParmVarDecl *P = FD->getParamDecl(idx);
    const Stmt *FirstUse = findFirstOutputUse(FD, P, Ctx);
    if (!FirstUse)
      continue;

    if (hasValidNullGuard(FD, P, FirstUse, Ctx))
      continue;

    PathDiagnosticLocation Loc =
        PathDiagnosticLocation::createBegin(FirstUse, Ctx.getSourceManager(),
                                            nullptr);
    auto Report = std::make_unique<BasicBugReport>(
        *BT, "Output pointer parameter is not checked for NULL before use.",
        Loc);
    BR.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects output pointer parameters used without a preceding NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "out_parameter_user": {
    "names": ["curl_easy_recv", "curl_easy_send"],
    "description": "Public API entry function that accepts a caller-provided output pointer and must validate it before writing or forwarding it"
  },
  "output_writer": {
    "names": ["Curl_easy_recv"],
    "description": "Helper function that writes a result through one of its pointer parameters"
  },
  "aborting_assert": {
    "names": [],
    "description": "Macro or function that aborts or returns when its condition is false, so the guarded pointer is non-null afterwards"
  }
}
*/
