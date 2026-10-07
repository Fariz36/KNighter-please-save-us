#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
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
#include "clang/Lex/Lexer.h"
#include "llvm/Support/Casting.h"

#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Tracks variables whose upper bound has been established by an aborting assertion.
REGISTER_MAP_WITH_PROGRAMSTATE(BoundedCountMap, const VarDecl *, unsigned)

namespace {

static bool isParserFunction(CheckerContext &C) {
  const Decl *D = C.getCurrentAnalysisDeclContext()->getDecl();
  if (!D)
    return false;

  const NamedDecl *ND = dyn_cast<NamedDecl>(D);
  return ND && knighter::declIsRole(ND, "parser_input");
}

static bool getVarDecl(const Expr *E, const VarDecl *&VD) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return false;

  VD = dyn_cast<VarDecl>(DRE->getDecl());
  return VD != nullptr;
}

static ProgramStateRef addBound(ProgramStateRef State, const VarDecl *VD,
                                uint64_t Bound) {
  if (!VD)
    return State;

  unsigned B = static_cast<unsigned>(Bound);
  const unsigned *Old = State->get<BoundedCountMap>(VD);
  if (Old && *Old <= B)
    return State;

  return State->set<BoundedCountMap>(VD, B);
}

static ProgramStateRef addBoundsFromCondition(ProgramStateRef State,
                                              const Expr *Cond,
                                              CheckerContext &C) {
  if (!Cond)
    return State;

  Cond = Cond->IgnoreParenImpCasts();

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_LAnd) {
      State = addBoundsFromCondition(State, BO->getLHS(), C);
      State = addBoundsFromCondition(State, BO->getRHS(), C);
      return State;
    }

    if (!BO->isComparisonOp())
      return State;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

    const VarDecl *VD = nullptr;
    const Expr *ConstExpr = nullptr;
    bool VarOnLeft = false;

    if (getVarDecl(LHS, VD)) {
      ConstExpr = RHS;
      VarOnLeft = true;
    } else if (getVarDecl(RHS, VD)) {
      ConstExpr = LHS;
      VarOnLeft = false;
    } else {
      return State;
    }

    llvm::APSInt Val;
    if (!EvaluateExprToInt(Val, ConstExpr, C) || Val.isNegative())
      return State;

    uint64_t CVal = Val.getZExtValue();

    switch (BO->getOpcode()) {
    case BO_LE:
      // V <= C
      if (VarOnLeft)
        return addBound(State, VD, CVal);
      break;
    case BO_LT:
      // V < C  <=>  V <= C - 1
      if (VarOnLeft && CVal > 0)
        return addBound(State, VD, CVal - 1);
      break;
    case BO_GE:
      // C >= V  <=>  V <= C
      if (!VarOnLeft)
        return addBound(State, VD, CVal);
      break;
    case BO_GT:
      // C > V  <=>  V < C  <=>  V <= C - 1
      if (!VarOnLeft && CVal > 0)
        return addBound(State, VD, CVal - 1);
      break;
    default:
      break;
    }
  }

  return State;
}

class SAGenTestChecker
    : public Checker<check::PreCall, check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Shift Overflow", "Undefined Behavior")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isParserFunction(C))
    return;

  bool DirectRole = knighter::callIsRole(Call, "aborting_assert");
  bool IsAbort = DirectRole;

  if (!IsAbort) {
    const Expr *OE = Call.getOriginExpr();
    if (OE) {
      StringRef MacroName = Lexer::getImmediateMacroName(
          OE->getExprLoc(), C.getSourceManager(), C.getLangOpts());
      for (const std::string &Name : knighter::roleNames("aborting_assert")) {
        if (MacroName == StringRef(Name)) {
          IsAbort = true;
          break;
        }
      }
    }
  }

  if (!IsAbort)
    return;

  ProgramStateRef State = C.getState();
  const Expr *Cond = nullptr;

  // If this is a direct aborting-assert call, its first argument is the
  // condition.  If we matched through the surrounding macro expansion, the
  // condition is usually the LHS of a `||` or the condition of a ternary.
  if (DirectRole && Call.getNumArgs() > 0) {
    Cond = Call.getArgExpr(0);
  }

  if (!Cond) {
    const Expr *OE = Call.getOriginExpr();
    if (OE) {
      if (const ConditionalOperator *CO =
              findSpecificTypeInParents<ConditionalOperator>(OE, C)) {
        Cond = CO->getCond();
      } else if (const BinaryOperator *BO =
                     findSpecificTypeInParents<BinaryOperator>(OE, C)) {
        if (BO->getOpcode() == BO_LOr) {
          // Typical assert macro expansion: (condition) || abort_call(...)
          Cond = BO->getLHS();
        }
      }
    }
  }

  if (Cond) {
    ProgramStateRef NewState = addBoundsFromCondition(State, Cond, C);
    if (NewState != State)
      C.addTransition(NewState);
  }
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO,
                                    CheckerContext &C) const {
  if (!isParserFunction(C))
    return;

  if (!BO || BO->getOpcode() != BO_Shl)
    return;

  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  const BinaryOperator *Mul = dyn_cast<BinaryOperator>(RHS);
  if (!Mul || Mul->getOpcode() != BO_Mul)
    return;

  const Expr *Op0 = Mul->getLHS()->IgnoreParenImpCasts();
  const Expr *Op1 = Mul->getRHS()->IgnoreParenImpCasts();

  const VarDecl *VD = nullptr;
  const Expr *ConstExpr = nullptr;

  if (getVarDecl(Op0, VD)) {
    ConstExpr = Op1;
  } else if (getVarDecl(Op1, VD)) {
    ConstExpr = Op0;
  } else {
    return;
  }

  llvm::APSInt KVal;
  if (!EvaluateExprToInt(KVal, ConstExpr, C) || KVal.isNegative())
    return;

  uint64_t K = KVal.getZExtValue();
  if (K == 0)
    return;

  QualType LType = BO->getLHS()->getType();
  if (!LType->isIntegerType())
    return;

  unsigned W = C.getASTContext().getTypeSize(LType);
  if (W == 0)
    return;

  uint64_t MaxAllowed = (W - 1) / K;

  ProgramStateRef State = C.getState();
  const unsigned *Bound = State->get<BoundedCountMap>(VD);
  if (Bound && *Bound <= MaxAllowed)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "shift amount may exceed bit width", N);
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects shift overflow caused by unbounded continuation-byte counts",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["utf8_decode"], "description": "function that parses/decodes untrusted input data"},
  "aborting_assert": {"names": ["lua_assert"], "description": "macro/function that aborts execution when its condition is false"},
  "null_on_failure": {"names": ["utf8_decode"], "description": "function that may return NULL on failure"}
}
*/
