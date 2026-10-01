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
#include "llvm/Support/Casting.h"

#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool stmtTextContains(const Stmt *S, StringRef Name, CheckerContext &C) {
  if (!S)
    return false;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(S->getSourceRange());
  StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
  return Text.contains(Name);
}

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

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Lua GC Use-After-Free", "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // 1. Filter calls to luaH_finishset.
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee || Callee->getName() != "luaH_finishset")
    return;

  // 2. Verify the enclosing function is luaV_finishset.
  const Decl *D = Call.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || FD->getName() != "luaV_finishset")
    return;

  // 3. Extract the table argument (index 1: luaH_finishset(L, h, key, val, hres)).
  const Expr *TableArg = Call.getArgExpr(1);
  if (!TableArg)
    return;

  // 4. Determine the table variable name.
  std::string TableName;
  if (const DeclRefExpr *DRE =
          dyn_cast<DeclRefExpr>(TableArg->IgnoreParenImpCasts())) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      TableName = VD->getNameAsString();
    }
  }
  if (TableName.empty()) {
    const SourceManager &SM = C.getSourceManager();
    const LangOptions &LangOpts = C.getLangOpts();
    CharSourceRange Range =
        CharSourceRange::getTokenRange(TableArg->getSourceRange());
    TableName = Lexer::getSourceText(Range, SM, LangOpts).str();
  }
  if (TableName.empty())
    return;

  // 5. Locate the call's enclosing CompoundStmt.
  const CallExpr *CE = dyn_cast<CallExpr>(Call.getOriginExpr());
  if (!CE)
    return;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(CE, C);
  if (!CS)
    return;

  // 6. Scan preceding statements in the compound statement for an anchor.
  bool Anchored = false;
  for (const Stmt *Child : CS->children()) {
    if (stmtContains(Child, CE))
      break;

    // Check by source text (robust against macro expansions).
    if (stmtTextContains(Child, "sethvalue2s", C) &&
        stmtTextContains(Child, TableName, C)) {
      Anchored = true;
      break;
    }

    // Also try the AST-based check as described in the plan.
    if (const Expr *PrevE = dyn_cast<Expr>(Child)) {
      if (ExprHasName(PrevE, "sethvalue2s", C) &&
          ExprHasName(PrevE, TableName, C)) {
        Anchored = true;
        break;
      }

      if (const CallExpr *PrevCE =
              dyn_cast<CallExpr>(PrevE->IgnoreParenImpCasts())) {
        if (ExprHasName(PrevCE, "sethvalue2s", C)) {
          for (unsigned i = 0; i < PrevCE->getNumArgs(); ++i) {
            if (ExprHasName(PrevCE->getArg(i), TableName, C)) {
              Anchored = true;
              break;
            }
          }
        }
      }
    }
    if (Anchored)
      break;
  }

  // Fallback: check the raw source text between the start of the block and
  // the start of the luaH_finishset call.
  if (!Anchored) {
    const SourceManager &SM = C.getSourceManager();
    const LangOptions &LangOpts = C.getLangOpts();
    SourceLocation CSStart = CS->getBeginLoc();
    SourceLocation CEStart = CE->getBeginLoc();
    if (CSStart.isValid() && CEStart.isValid()) {
      CharSourceRange Range = CharSourceRange::getCharRange(CSStart, CEStart);
      StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
      if (Text.contains("sethvalue2s") && Text.contains(TableName)) {
        Anchored = true;
      }
    }
  }

  if (Anchored)
    return;

  // 7. Report the bug.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Lua table not anchored before luaH_finishset; possible use-after-free "
      "due to emergency GC",
      N);
  Report->addRange(CE->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing anchoring of Lua tables before luaH_finishset calls",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
