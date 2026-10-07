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
#include "clang/Lex/Lexer.h"
#include "knighter/roles.h"
#include "llvm/ADT/SmallVector.h"

#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PostStmt<CStyleCastExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked Narrowing of UTF-8 Length",
                       "Integer Overflow")) {}

  void checkPostStmt(const CStyleCastExpr *CE, CheckerContext &C) const;
};

} // end anonymous namespace

static bool stmtTextContainsName(const Stmt *S, llvm::StringRef Name,
                                 CheckerContext &C) {
  if (!S || Name.empty())
    return false;

  SourceRange SR = S->getSourceRange();
  if (SR.isInvalid())
    return false;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(SR);
  llvm::StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
  return Text.contains(Name);
}

static bool containsDeclRef(const Stmt *S, const VarDecl *VD) {
  if (!S || !VD)
    return false;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (DRE->getDecl() == VD)
      return true;
  }

  for (const Stmt *Child : S->children()) {
    if (containsDeclRef(Child, VD))
      return true;
  }
  return false;
}

static void collectPointerDeclRefs(
    const Expr *E, llvm::SmallVectorImpl<const VarDecl *> &Vars) {
  if (!E)
    return;

  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (VD->getType()->isPointerType())
        Vars.push_back(VD);
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const auto *ChildE = dyn_cast<Expr>(Child))
      collectPointerDeclRefs(ChildE, Vars);
  }
}

void SAGenTestChecker::checkPostStmt(const CStyleCastExpr *CE,
                                     CheckerContext &C) const {
  if (!CE)
    return;

  ASTContext &AC = C.getASTContext();
  QualType DestTy = CE->getType();
  if (!DestTy->isIntegerType() || !DestTy->isSignedIntegerType() ||
      AC.getTypeSize(DestTy) != 32) {
    return;
  }

  const Expr *Sub = CE->getSubExpr();
  if (!Sub)
    return;

  // If the cast operand already contains a clamp, the fix is present.
  for (const std::string &ClampName : knighter::roleNames("clamp")) {
    if (ExprHasName(Sub, llvm::StringRef(ClampName.data(), ClampName.size()),
                    C)) {
      return;
    }
  }

  const Expr *Operand = Sub->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Operand);
  if (!BO || BO->getOpcode() != BO_Sub)
    return;

  llvm::SmallVector<const VarDecl *, 4> PtrVars;
  collectPointerDeclRefs(BO->getLHS(), PtrVars);
  collectPointerDeclRefs(BO->getRHS(), PtrVars);
  if (PtrVars.empty())
    return;

  const CompoundStmt *Body = findSpecificTypeInParents<CompoundStmt>(CE, C);
  if (!Body)
    return;

  const SourceManager &SM = C.getSourceManager();
  SourceLocation CastLoc = CE->getBeginLoc();
  if (!CastLoc.isValid())
    return;

  for (const Stmt *S : Body->body()) {
    if (!S)
      continue;

    SourceLocation SLoc = S->getBeginLoc();
    if (!SLoc.isValid() || !SM.isBeforeInTranslationUnit(SLoc, CastLoc))
      continue;

    const auto *WS = dyn_cast<WhileStmt>(S);
    if (!WS)
      continue;

    bool HasParserInput = false;
    for (const std::string &ParserName : knighter::roleNames("parser_input")) {
      if (stmtTextContainsName(
              WS, llvm::StringRef(ParserName.data(), ParserName.size()), C)) {
        HasParserInput = true;
        break;
      }
    }
    if (!HasParserInput)
      continue;

    for (const VarDecl *VD : PtrVars) {
      if (containsDeclRef(WS, VD)) {
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N)
          return;

        auto Report = std::make_unique<PathSensitiveBugReport>(
            *BT,
            "Unchecked narrowing of UTF-8 byte length to int; missing clamp "
            "before cast",
            N);
        Report->addRange(CE->getSourceRange());
        C.emitReport(std::move(Report));
        return;
      }
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked narrowing of UTF-8 byte length to int before cast",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "clamp": {"names": ["MIN"], "description": "macro that returns the minimum of two values; used to clamp a length before narrowing"},
  "parser_input": {"names": ["SQLITE_SKIP_UTF8"], "description": "macro that advances a pointer over one UTF-8 code point in a string"}
}
*/
