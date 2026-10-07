#include <memory>
#include <string>

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
#include "clang/AST/Decl.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Lex/MacroInfo.h"
#include "clang/Lex/Token.h"
#include "llvm/ADT/ArrayRef.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::ASTDecl<FunctionDecl>> {
  mutable std::unique_ptr<BugType> BT;
  mutable bool CheckedMacros = false;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked Lookahead Read", "Security")) {}

  void checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr,
                    BugReporter &BR) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr,
                                    BugReporter &BR) const {
  if (CheckedMacros)
    return;
  CheckedMacros = true;

  Preprocessor &PP = Mgr.getPreprocessor();
  auto LookaheadNames = knighter::roleNames("lookahead");
  auto LengthNames = knighter::roleNames("length_of");

  for (Preprocessor::macro_iterator I = PP.macro_begin(), E = PP.macro_end();
       I != E; ++I) {
    const IdentifierInfo *II = I->first;
    if (!II)
      continue;

    StringRef MacroName = II->getName();
    bool IsLookahead = false;
    for (const auto &RoleName : LookaheadNames) {
      if (MacroName == StringRef(RoleName)) {
        IsLookahead = true;
        break;
      }
    }
    if (!IsLookahead)
      continue;

    const MacroDirective *MD = I->second.getLatest();
    if (!MD)
      continue;
    const MacroInfo *MI = MD->getMacroInfo();
    if (!MI || !MI->isFunctionLike())
      continue;

    bool HasLength = false;
    bool HasComparison = false;
    for (const Token &Tok : MI->tokens()) {
      if (Tok.is(tok::identifier)) {
        if (const IdentifierInfo *TII = Tok.getIdentifierInfo()) {
          StringRef TokName = TII->getName();
          for (const auto &RoleName : LengthNames) {
            if (TokName == StringRef(RoleName)) {
              HasLength = true;
              break;
            }
          }
        }
      } else if (Tok.is(tok::less) || Tok.is(tok::lessequal) ||
                 Tok.is(tok::greater) || Tok.is(tok::greaterequal) ||
                 Tok.is(tok::equalequal) || Tok.is(tok::exclaimequal)) {
        HasComparison = true;
      }
    }

    if (HasLength && HasComparison)
      continue;

    SourceLocation Loc = MI->getDefinitionLoc();
    PathDiagnosticLocation PDL(Loc, Mgr.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, "Lookahead macro lacks bounds check against length", PDL);
    BR.emitReport(std::move(Report));
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects lookahead macros that perform indexed reads without a bounds check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "lookahead": {"names": ["NXT"], "description": "macro that performs an indexed lookahead read from the parser cursor"},
  "length_of": {"names": ["len"], "description": "field storing the length of the input buffer"}
}
*/
