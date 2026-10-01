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

#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool isGitErrorSet(const CallEvent &Call, CheckerContext &C) {
  const Expr *OriginExpr = Call.getOriginExpr();
  return OriginExpr && ExprHasName(OriginExpr, "git_error_set", C);
}

static void findFormatStringArgIndices(
    StringRef Format, unsigned FirstVarArg,
    llvm::SmallVectorImpl<unsigned> &Indices) {
  unsigned ArgIdx = FirstVarArg;

  for (size_t i = 0; i < Format.size(); ++i) {
    if (Format[i] != '%')
      continue;

    if (i + 1 < Format.size() && Format[i + 1] == '%') {
      ++i;
      continue;
    }

    ++i; // skip '%'

    // Skip flags.
    while (i < Format.size() &&
           (Format[i] == '-' || Format[i] == '+' || Format[i] == ' ' ||
            Format[i] == '#' || Format[i] == '0'))
      ++i;

    // Width.
    if (i < Format.size() && Format[i] == '*') {
      ++ArgIdx; // width argument
      ++i;
    } else {
      while (i < Format.size() && Format[i] >= '0' && Format[i] <= '9')
        ++i;
    }

    // Precision.
    if (i < Format.size() && Format[i] == '.') {
      ++i;
      if (i < Format.size() && Format[i] == '*') {
        ++ArgIdx; // precision argument
        ++i;
      } else {
        while (i < Format.size() && Format[i] >= '0' && Format[i] <= '9')
          ++i;
      }
    }

    // Length modifiers.
    if (i < Format.size()) {
      switch (Format[i]) {
      case 'h':
        ++i;
        if (i < Format.size() && Format[i] == 'h')
          ++i;
        break;
      case 'l':
        ++i;
        if (i < Format.size() && Format[i] == 'l')
          ++i;
        break;
      case 'j':
      case 'z':
      case 't':
      case 'L':
        ++i;
        break;
      default:
        break;
      }
    }

    if (i >= Format.size())
      break;

    char Conv = Format[i];
    if (Conv == 's') {
      Indices.push_back(ArgIdx);
      ++ArgIdx;
    } else if (Conv == 'm') {
      // %m consumes no argument.
    } else if (Conv == '%') {
      // Already handled.
    } else {
      // All other conversions consume one argument.
      ++ArgIdx;
    }
  }
}

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Potential NULL passed to %s", "Null Pointer")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isGitErrorSet(Call, C))
    return;

  if (Call.getNumArgs() < 3)
    return;

  const Expr *FmtExpr = Call.getArgExpr(1);
  if (!FmtExpr)
    return;

  FmtExpr = FmtExpr->IgnoreParenImpCasts();
  const StringLiteral *SL = dyn_cast<StringLiteral>(FmtExpr);
  if (!SL)
    return;

  llvm::SmallVector<unsigned, 4> PercentSArgs;
  findFormatStringArgIndices(SL->getString(), 2, PercentSArgs);

  if (PercentSArgs.empty())
    return;

  ProgramStateRef State = C.getState();

  for (unsigned Idx : PercentSArgs) {
    if (Idx >= Call.getNumArgs())
      continue;

    const Expr *ArgExpr = Call.getArgExpr(Idx);
    if (!ArgExpr)
      continue;

    QualType ArgTy = ArgExpr->getType();
    if (!ArgTy->isPointerType())
      continue;

    SVal ArgVal = Call.getArgSVal(Idx);
    ConditionTruthVal NonNull = State->isNonNull(ArgVal);
    if (NonNull.isConstrained() && NonNull.getValue())
      continue;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Potential NULL passed to %s format directive", N);
    report->addRange(ArgExpr->getSourceRange());
    C.emitReport(std::move(report));

    // Avoid duplicate reports for the same call.
    break;
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potentially NULL pointer passed to %s format directive",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
