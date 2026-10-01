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

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Casting.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Use-after-free in luaV_finishset",
                       "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

static StringRef getStmtText(const Stmt *S, CheckerContext &C) {
  if (!S)
    return StringRef();

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(S->getSourceRange());
  return Lexer::getSourceText(Range, SM, LangOpts);
}

static bool containsStmt(const Stmt *Parent, const Stmt *Child) {
  if (!Parent || !Child)
    return false;

  if (Parent == Child)
    return true;

  for (const Stmt *S : Parent->children()) {
    if (containsStmt(S, Child))
      return true;
  }

  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const LocationContext *LC = C.getLocationContext();
  if (!LC)
    return;

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(LC->getDecl());
  if (!FD || FD->getNameAsString() != "luaV_finishset")
    return;

  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "luaH_finishset", C))
    return;

  const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
  if (!CE || CE->getNumArgs() <= 1)
    return;

  const Expr *TableExpr = CE->getArg(1);
  if (!TableExpr)
    return;

  StringRef TableText = getStmtText(TableExpr, C);
  if (TableText.empty())
    return;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(CE, C);
  if (!CS)
    return;

  llvm::SmallVector<const Stmt *, 8> Body;
  for (const Stmt *S : CS->body())
    Body.push_back(S);

  int CallIdx = -1;
  for (unsigned I = 0; I < Body.size(); ++I) {
    if (Body[I] == CE || containsStmt(Body[I], CE)) {
      CallIdx = static_cast<int>(I);
      break;
    }
  }

  if (CallIdx < 0)
    return;

  bool Anchored = false;

  if (CallIdx >= 2 && CallIdx + 1 < static_cast<int>(Body.size())) {
    StringRef Before2 = getStmtText(Body[CallIdx - 2], C);
    StringRef Before1 = getStmtText(Body[CallIdx - 1], C);
    StringRef After1 = getStmtText(Body[CallIdx + 1], C);

    if (Before2.contains("sethvalue2s") &&
        Before2.contains("L->top.p") &&
        Before2.contains(TableText) &&
        Before1.contains("L->top.p") &&
        Before1.contains("++") &&
        After1.contains("L->top.p") &&
        After1.contains("--")) {
      Anchored = true;
    }
  }

  if (Anchored)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Table passed to luaH_finishset is not anchored on Lua stack; possible use-after-free.",
      N);
  Report->addRange(CE->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unanchored tables passed to luaH_finishset in luaV_finishset",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
