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
#include <cctype>
#include <cstring>
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "NULL argument for %s directive",
                       "Null Format Argument")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void checkFormatString(const CallEvent &Call, CheckerContext &C,
                         const StringLiteral *SL, unsigned FirstVarArgIdx) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "git_error_set", C))
    return;

  if (Call.getNumArgs() <= 1)
    return;

  const Expr *FmtExpr = Call.getArgExpr(1);
  if (!FmtExpr)
    return;

  const StringLiteral *SL =
      dyn_cast<StringLiteral>(FmtExpr->IgnoreParenImpCasts());
  if (!SL)
    return;

  // git_error_set(int klass, const char *fmt, ...)
  // The first variadic argument is at index 2.
  checkFormatString(Call, C, SL, 2);
}

void SAGenTestChecker::checkFormatString(const CallEvent &Call,
                                         CheckerContext &C,
                                         const StringLiteral *SL,
                                         unsigned FirstVarArgIdx) const {
  StringRef Fmt = SL->getString();
  unsigned ArgIdx = FirstVarArgIdx;

  const char *P = Fmt.begin();
  const char *E = Fmt.end();

  while (P < E) {
    if (*P++ != '%')
      continue;

    if (P < E && *P == '%') {
      ++P;
      continue;
    }

    // Skip flags.
    while (P < E && (*P == '-' || *P == '+' || *P == ' ' || *P == '#' ||
                     *P == '0'))
      ++P;

    // Width: either '*' (consumes an argument) or digits.
    if (P < E && *P == '*') {
      ++ArgIdx;
      ++P;
    } else {
      while (P < E && std::isdigit(static_cast<unsigned char>(*P)))
        ++P;
    }

    // Precision: '.' followed by '*' or digits.
    if (P < E && *P == '.') {
      ++P;
      if (P < E && *P == '*') {
        ++ArgIdx;
        ++P;
      } else {
        while (P < E && std::isdigit(static_cast<unsigned char>(*P)))
          ++P;
      }
    }

    // Length modifiers.
    while (P < E && (strchr("hlLjztq", *P) != nullptr))
      ++P;

    if (P >= E)
      break;

    char Spec = *P++;

    if (Spec == 's') {
      if (ArgIdx < Call.getNumArgs()) {
        const Expr *ArgExpr = Call.getArgExpr(ArgIdx);
        if (ArgExpr) {
          const Expr *ArgNoImp = ArgExpr->IgnoreParenImpCasts();
          if (ArgNoImp->getType()->isPointerType() &&
              !isa<StringLiteral>(ArgNoImp) &&
              !ArgNoImp->getType()->isArrayType()) {
            SVal ArgSVal = Call.getArgSVal(ArgIdx);
            if (!ArgSVal.isUnknown() && ArgSVal.getAs<Loc>()) {
              if (auto ArgVal = ArgSVal.getAs<DefinedOrUnknownSVal>()) {
                ProgramStateRef State = C.getState();
                if (State->assume(*ArgVal, false)) {
                  ExplodedNode *N = C.generateNonFatalErrorNode();
                  if (!N)
                    return;

                  auto Report = std::make_unique<PathSensitiveBugReport>(
                      *BT,
                      "Potential NULL argument passed to %s format directive", N);
                  Report->addRange(ArgExpr->getSourceRange());
                  C.emitReport(std::move(Report));
                  return;
                }
              }
            }
          }
        }
      }
    }

    // Consume the argument for this conversion. The GNU '%m' extension
    // does not take an argument.
    if (Spec != 'm')
      ++ArgIdx;
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potentially NULL arguments passed to %s format directives",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
