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

#include "clang/Lex/Preprocessor.h"
#include "clang/Lex/MacroInfo.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool isComparisonToken(const Token &Tok) {
  return Tok.is(tok::less) || Tok.is(tok::lessequal) ||
         Tok.is(tok::greater) || Tok.is(tok::greaterequal) ||
         Tok.is(tok::equalequal) || Tok.is(tok::exclaimequal);
}

static bool isConditionBoundary(const Token &Tok) {
  return Tok.is(tok::ampamp) || Tok.is(tok::pipepipe) ||
         Tok.is(tok::question) || Tok.is(tok::colon);
}

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;
  mutable bool CheckedMacros = false;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked indexed read", "Out-of-bounds read")) {}

  void checkASTCodeBody(const Decl *,
                        AnalysisManager &Mgr,
                        BugReporter &BR) const;

private:
  bool macroHasBoundsCheck(const MacroInfo *MI) const;

  void reportUncheckedIndexedRead(const MacroInfo *MI,
                                  BugReporter &BR) const;
};

bool SAGenTestChecker::macroHasBoundsCheck(const MacroInfo *MI) const {
  if (!MI || !MI->isFunctionLike())
    return true;

  auto Params = MI->params();
  if (Params.empty())
    return true;

  const IdentifierInfo *IndexParam = Params.back();
  if (!IndexParam)
    return true;

  auto Tokens = MI->tokens();

  size_t QuestionIdx = Tokens.size();
  for (size_t I = 0; I < Tokens.size(); ++I) {
    if (Tokens[I].is(tok::question)) {
      QuestionIdx = I;
      break;
    }
  }

  // No conditional expression: the indexed read is not guarded.
  if (QuestionIdx == Tokens.size())
    return false;

  // Look for a comparison in the condition part that involves the index
  // parameter. If no such comparison exists, the macro is considered unguarded.
  for (size_t I = 0; I < QuestionIdx; ++I) {
    if (!isComparisonToken(Tokens[I]))
      continue;

    // Scan left from the comparison operator.
    for (size_t J = I; J > 0; --J) {
      const Token &T = Tokens[J - 1];
      if (isConditionBoundary(T))
        break;
      if (T.is(tok::identifier) && T.getIdentifierInfo() == IndexParam)
        return true;
    }

    // Scan right from the comparison operator.
    for (size_t J = I + 1; J < QuestionIdx; ++J) {
      const Token &T = Tokens[J];
      if (isConditionBoundary(T))
        break;
      if (T.is(tok::identifier) && T.getIdentifierInfo() == IndexParam)
        return true;
    }
  }

  return false;
}

void SAGenTestChecker::reportUncheckedIndexedRead(const MacroInfo *MI,
                                                  BugReporter &BR) const {
  if (!BT || !MI)
    return;

  PathDiagnosticLocation L(MI->getDefinitionLoc(), BR.getSourceManager());
  auto Report = std::make_unique<BasicBugReport>(
      *BT,
      "Unchecked indexed read: macro does not verify the index is within the "
      "buffer length.",
      L);

  BR.emitReport(std::move(Report));
}

void SAGenTestChecker::checkASTCodeBody(const Decl *,
                                        AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  if (CheckedMacros)
    return;
  CheckedMacros = true;

  Preprocessor &PP = Mgr.getPreprocessor();

  for (const auto &Name : knighter::roleNames("indexed_read")) {
    IdentifierInfo *II = PP.getIdentifierInfo(Name);
    if (!II)
      continue;

    const MacroInfo *MI = PP.getMacroInfo(II);
    if (!MI || !MI->isFunctionLike())
      continue;

    if (!macroHasBoundsCheck(MI)) {
      reportUncheckedIndexedRead(MI, BR);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects indexed-read macros that do not verify the index is within the "
      "buffer length",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "indexed_read": {
    "names": ["NXT"],
    "description": "Macro that performs an indexed read from a buffer; its expansion must verify the index is within the buffer's valid length."
  },
  "length_of": {
    "names": ["strlen"],
    "description": "Function that returns the length of a string, used to compute a buffer's valid length."
  }
}
*/
