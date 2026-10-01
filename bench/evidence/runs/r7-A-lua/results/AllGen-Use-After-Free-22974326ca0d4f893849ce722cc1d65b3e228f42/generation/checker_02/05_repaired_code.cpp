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
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "GC object not anchored before luaH_finishset",
                       "Lua GC")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "luaH_finishset", C))
    return;

  const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
  if (!CE || CE->getNumArgs() < 2)
    return;

  // The second argument is the Table *h that should be anchored.
  const Expr *Arg1 = CE->getArg(1)->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Arg1);
  if (!DRE)
    return;

  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return;

  StringRef VarName = VD->getName();
  if (VarName.empty())
    return;

  // Find the nearest enclosing compound statement.
  const CompoundStmt *CS =
      findSpecificTypeInParents<CompoundStmt>(static_cast<const Stmt *>(CE), C);
  if (!CS)
    return;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();

  bool FoundAnchor = false;
  for (const Stmt *S : CS->body()) {
    // Check only statements that appear before the call.
    if (!SM.isBeforeInTranslationUnit(S->getEndLoc(), CE->getBeginLoc())) {
      // Reached the statement containing the call, or a later one.
      break;
    }

    CharSourceRange Range = CharSourceRange::getTokenRange(S->getSourceRange());
    StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
    if (Text.contains("sethvalue2s") && Text.contains(VarName)) {
      FoundAnchor = true;
      break;
    }
  }

  if (FoundAnchor)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "GC object not anchored before luaH_finishset", N);
  Report->addRange(CE->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing anchoring of a table before luaH_finishset, which can "
      "lead to use-after-free during emergency GC",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
