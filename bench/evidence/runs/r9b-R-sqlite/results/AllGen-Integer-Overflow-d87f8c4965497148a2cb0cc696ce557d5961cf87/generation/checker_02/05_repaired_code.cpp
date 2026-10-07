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
#include "clang/Lex/Lexer.h"
#include "knighter/roles.h"
#include "llvm/ADT/SmallVector.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Collects all loop statements in a function body.
class LoopCollector : public RecursiveASTVisitor<LoopCollector> {
  llvm::SmallVector<const Stmt *, 8> Loops;

public:
  bool VisitWhileStmt(WhileStmt *S) {
    Loops.push_back(S);
    return true;
  }
  bool VisitForStmt(ForStmt *S) {
    Loops.push_back(S);
    return true;
  }
  bool VisitDoStmt(DoStmt *S) {
    Loops.push_back(S);
    return true;
  }
  const llvm::SmallVector<const Stmt *, 8> &getLoops() const { return Loops; }
};

// Checks whether a loop modifies a given variable.
class VarModifierVisitor : public RecursiveASTVisitor<VarModifierVisitor> {
  const VarDecl *VD;
  bool Found = false;

public:
  explicit VarModifierVisitor(const VarDecl *VD) : VD(VD) {}
  bool found() const { return Found; }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (Found)
      return false;
    if (UO->isIncrementDecrementOp()) {
      const Expr *E = UO->getSubExpr()->IgnoreParenCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
        if (DRE->getDecl() == VD) {
          Found = true;
          return false;
        }
      }
    }
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (Found)
      return false;
    if (BO->isAssignmentOp()) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (DRE->getDecl() == VD) {
          Found = true;
          return false;
        }
      }
    }
    return true;
  }
};

// Checks whether a variable is used as an argument to a buffer_copy call.
class BufferCopyFinder : public RecursiveASTVisitor<BufferCopyFinder> {
  const VarDecl *VD;
  ASTContext &Ctx;
  bool Found = false;

public:
  BufferCopyFinder(const VarDecl *VD, ASTContext &Ctx) : VD(VD), Ctx(Ctx) {}
  bool found() const { return Found; }

  bool VisitCallExpr(CallExpr *CE) {
    if (Found)
      return false;
    if (knighter::callExprIsRole(CE, "buffer_copy", Ctx)) {
      for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
        const Expr *Arg = CE->getArg(i)->IgnoreParenCasts();
        if (const auto *DRE = dyn_cast<DeclRefExpr>(Arg)) {
          if (DRE->getDecl() == VD) {
            Found = true;
            return false;
          }
        }
      }
    }
    return true;
  }
};

static bool isSignedInt32(QualType Ty, ASTContext &Ctx) {
  if (!Ty->isIntegerType())
    return false;
  if (Ctx.getTypeSize(Ty) != 32)
    return false;
  return Ty->isSignedIntegerType();
}

static const VarDecl *getVarDecl(const Expr *E) {
  E = E->IgnoreParenCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    return dyn_cast<VarDecl>(DRE->getDecl());
  }
  return nullptr;
}

static bool loopContainsParserInput(const Stmt *S, ASTContext &Ctx) {
  const SourceManager &SM = Ctx.getSourceManager();
  const LangOptions &LangOpts = Ctx.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(S->getSourceRange());
  if (!Range.isValid())
    return false;
  StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
  for (const std::string &Name : knighter::roleNames("parser_input")) {
    if (Text.contains(Name))
      return true;
  }
  return false;
}

static bool loopModifiesVar(const Stmt *S, const VarDecl *VD) {
  if (!VD)
    return false;
  VarModifierVisitor V(VD);
  V.TraverseStmt(const_cast<Stmt *>(S));
  return V.found();
}

static bool isLengthUsedInBufferCopy(const Stmt *Body, const VarDecl *VD,
                                     ASTContext &Ctx) {
  if (!VD)
    return false;
  BufferCopyFinder V(VD, Ctx);
  V.TraverseStmt(const_cast<Stmt *>(Body));
  return V.found();
}

class AssignmentVisitor : public RecursiveASTVisitor<AssignmentVisitor> {
  ASTContext &Ctx;
  SourceManager &SM;
  BugReporter &BR;
  BugType &BT;
  const llvm::SmallVector<const Stmt *, 8> &Loops;
  const Stmt *FuncBody;

public:
  AssignmentVisitor(ASTContext &Ctx, SourceManager &SM,
                    BugReporter &BR, BugType &BT,
                    const llvm::SmallVector<const Stmt *, 8> &Loops,
                    const Stmt *FuncBody)
      : Ctx(Ctx), SM(SM), BR(BR), BT(BT), Loops(Loops),
        FuncBody(FuncBody) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Assign)
      return true;

    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const auto *DRE = dyn_cast<DeclRefExpr>(LHS);
    if (!DRE)
      return true;

    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return true;

    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
    const auto *CE = dyn_cast<CastExpr>(RHS);
    if (!CE)
      return true;
    if (!isSignedInt32(CE->getType(), Ctx))
      return true;

    const Expr *Sub = CE->getSubExpr()->IgnoreParenCasts();
    const auto *SubBO = dyn_cast<BinaryOperator>(Sub);
    if (!SubBO || SubBO->getOpcode() != BO_Sub)
      return true;
    if (!SubBO->getLHS()->getType()->isPointerType() ||
        !SubBO->getRHS()->getType()->isPointerType())
      return true;

    const VarDecl *VarL = getVarDecl(SubBO->getLHS());
    const VarDecl *VarR = getVarDecl(SubBO->getRHS());
    if (!VarL && !VarR)
      return true;

    bool FoundLoop = false;
    for (const Stmt *Loop : Loops) {
      if (!loopContainsParserInput(Loop, Ctx))
        continue;
      if (!SM.isBeforeInTranslationUnit(Loop->getEndLoc(), CE->getBeginLoc()))
        continue;
      if (VarL && loopModifiesVar(Loop, VarL)) {
        FoundLoop = true;
        break;
      }
      if (VarR && loopModifiesVar(Loop, VarR)) {
        FoundLoop = true;
        break;
      }
    }
    if (!FoundLoop)
      return true;

    if (!isLengthUsedInBufferCopy(FuncBody, VD, Ctx))
      return true;

    PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(CE, SM, nullptr);
    auto Report = std::make_unique<BasicBugReport>(
        BT, "Unchecked narrowing of length from parser_input scan", Loc);
    Report->addRange(CE->getSourceRange());
    BR.emitReport(std::move(Report));

    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked Narrowing of Length",
                       "Integer Overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  ASTContext &Ctx = Mgr.getASTContext();
  SourceManager &SM = Ctx.getSourceManager();

  LoopCollector LC;
  LC.TraverseStmt(const_cast<Stmt *>(Body));
  const auto &Loops = LC.getLoops();

  AssignmentVisitor V(Ctx, SM, BR, *BT, Loops, Body);
  V.TraverseStmt(const_cast<Stmt *>(Body));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked narrowing of length from parser_input scan", "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["SQLITE_SKIP_UTF8"], "description": "advances a pointer over UTF-8 input and can consume multiple bytes per step"},
  "buffer_copy": {"names": ["sqlite3_str_append", "sqlite3_str_appendchar"], "description": "consumes a byte length to append/pad output"}
}
*/
