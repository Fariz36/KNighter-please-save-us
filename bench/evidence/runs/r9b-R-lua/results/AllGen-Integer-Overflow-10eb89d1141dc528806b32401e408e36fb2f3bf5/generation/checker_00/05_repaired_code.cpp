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
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker
    : public Checker<check::PreStmt<BinaryOperator>, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Shift overflow", "Undefined behavior")) {}

  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportShiftOverflow(const BinaryOperator *BO, CheckerContext &C) const;
};

} // end anonymous namespace

static bool extractShiftAmount(const Expr *E, const Expr *&Var,
                               llvm::APSInt &Factor) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    Var = DRE;
    Factor = llvm::APSInt(llvm::APInt(64, 1), true);
    return true;
  }

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Mul) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

      const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(L);
      const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(R);
      if (IL && DRE) {
        Var = DRE;
        Factor = llvm::APSInt(IL->getValue(), true);
        return true;
      }

      IL = dyn_cast<IntegerLiteral>(R);
      DRE = dyn_cast<DeclRefExpr>(L);
      if (IL && DRE) {
        Var = DRE;
        Factor = llvm::APSInt(IL->getValue(), true);
        return true;
      }
    }
  }

  return false;
}

void SAGenTestChecker::reportShiftOverflow(const BinaryOperator *BO,
                                           CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Shift amount may exceed bit width before validation", N);
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO,
                                    CheckerContext &C) const {
  if (!BO || BO->getOpcode() != BO_Shl)
    return;

  const Decl *D = C.getCurrentAnalysisDeclContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || !knighter::declIsRole(FD, "parser_input"))
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();
  if (!LHS || !RHS)
    return;

  QualType LHSType = LHS->getType();
  if (!LHSType->isIntegerType())
    return;

  unsigned Width = C.getASTContext().getTypeSize(LHSType);
  if (Width == 0 || Width > 64)
    return;

  llvm::APSInt ConstVal;
  if (EvaluateExprToInt(ConstVal, RHS, C)) {
    if (ConstVal.isNegative() || ConstVal.getBitWidth() > 64 ||
        ConstVal.getZExtValue() >= Width) {
      reportShiftOverflow(BO, C);
    }
    return;
  }

  const Expr *Var = nullptr;
  llvm::APSInt Factor;
  if (!extractShiftAmount(RHS, Var, Factor)) {
    reportShiftOverflow(BO, C);
    return;
  }

  if (Factor.isNegative() || Factor.getBitWidth() > 64) {
    reportShiftOverflow(BO, C);
    return;
  }
  uint64_t FactorVal = Factor.getZExtValue();

  SVal V = C.getState()->getSVal(Var, C.getLocationContext());

  // Concrete shift amount: check directly.
  if (auto CI = V.getAs<nonloc::ConcreteInt>()) {
    const llvm::APSInt &Val = CI->getValue();
    if (Val.isNegative() || Val.getBitWidth() > 64) {
      reportShiftOverflow(BO, C);
      return;
    }
    uint64_t ValU = Val.getZExtValue();
    if (FactorVal != 0 && ValU > (Width / FactorVal)) {
      reportShiftOverflow(BO, C);
      return;
    }
    if (ValU * FactorVal >= Width) {
      reportShiftOverflow(BO, C);
      return;
    }
    return;
  }

  SymbolRef Sym = V.getAsSymbol();
  if (!Sym) {
    reportShiftOverflow(BO, C);
    return;
  }

  const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C);
  if (!Max) {
    reportShiftOverflow(BO, C);
    return;
  }

  if (Max->isNegative() || Max->getBitWidth() > 64) {
    reportShiftOverflow(BO, C);
    return;
  }

  uint64_t MaxVal = Max->getZExtValue();
  if (FactorVal != 0 && MaxVal > (Width / FactorVal)) {
    reportShiftOverflow(BO, C);
    return;
  }
  if (MaxVal * FactorVal >= Width) {
    reportShiftOverflow(BO, C);
    return;
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "aborting_assert"))
    return;

  if (Call.getNumArgs() < 1)
    return;

  SVal Cond = Call.getArgSVal(0);
  if (Cond.isUndef())
    return;

  ProgramStateRef State = C.getState();
  if (ProgramStateRef TrueState = State->assume(Cond.castAs<DefinedOrUnknownSVal>(), true)) {
    C.addTransition(TrueState);
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects shift amounts that may exceed the bit width before validation in "
      "parser input functions",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {
    "names": ["utf8_decode"],
    "description": "function that parses an untrusted byte/character sequence and returns a pointer or status"
  },
  "aborting_assert": {
    "names": ["lua_assert"],
    "description": "macro/function that aborts execution when its condition is false, so the condition is true on the continuing path"
  }
}
*/
