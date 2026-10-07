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
#include "clang/Lex/Lexer.h"
#include "knighter/roles.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PostStmt<ArraySubscriptExpr>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read", "Memory Error")) {}

  void checkPostStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostStmt(const ArraySubscriptExpr *ASE,
                                     CheckerContext &C) const {
  if (!ASE)
    return;

  SourceLocation Loc = ASE->getBeginLoc();
  if (Loc.isInvalid())
    return;

  // Identify if this subscript is a parser-input lookahead macro.
  StringRef MacroName = Lexer::getImmediateMacroName(
      Loc, C.getSourceManager(), C.getLangOpts());
  if (MacroName.empty())
    return;

  bool IsParserInput = false;
  for (const std::string &RoleName : knighter::roleNames("parser_input")) {
    if (MacroName == RoleName) {
      IsParserInput = true;
      break;
    }
  }
  if (!IsParserInput)
    return;

  // If the access is wrapped in a conditional operator, assume it is guarded.
  if (findSpecificTypeInParents<ConditionalOperator>(ASE, C))
    return;

  // Otherwise, report a potential out-of-bounds read.
  if (!BT)
    return;

  auto Report = std::make_unique<BasicBugReport>(
      *BT, "Parser input lookahead may read out of bounds",
      PathDiagnosticLocation::createBegin(ASE, C.getSourceManager(),
                                          C.getLocationContext()));
  Report->addRange(ASE->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects out-of-bounds reads in parser input lookahead macros",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {
    "names": ["NXT"],
    "description": "macro or function that reads a character from the parser input buffer at a computed offset (lookahead)"
  },
  "length_of": {
    "names": ["strlen"],
    "description": "computes the length of a string or buffer"
  },
  "duplicator": {
    "names": ["xmlStrdup"],
    "description": "creates a new copy of a string or buffer"
  },
  "null_on_failure": {
    "names": ["xmlStrdup"],
    "description": "may return NULL to signal failure"
  }
}
*/
