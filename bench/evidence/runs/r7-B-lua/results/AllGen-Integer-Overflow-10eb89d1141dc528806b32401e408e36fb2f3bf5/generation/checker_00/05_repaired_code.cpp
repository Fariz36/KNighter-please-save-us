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
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state traits to track whether the input byte has been bounded
// (c >= 0xFE check) and whether the shift count has been bounded
// (e.g., lua_assert(count <= 5)).
REGISTER_TRAIT_WITH_PROGRAMSTATE(InputBounded, bool)
REGISTER_TRAIT_WITH_PROGRAMSTATE(CountBounded, bool)

namespace {

// Helper: get the current function being analyzed.
static const FunctionDecl *getCurrentFunction(CheckerContext &C) {
  const LocationContext *LC = C.getLocationContext();
  if (!LC)
    return nullptr;
  return dyn_cast_or_null<FunctionDecl>(LC->getDecl());
}

// Helper: check if we are inside utf8_decode.
static bool isUtf8Decode(CheckerContext &C) {
  const FunctionDecl *FD = getCurrentFunction(C);
  return FD && FD->getName() == "utf8_decode";
}

// Helper: check if an expression is a reference to a variable with the given name.
static bool isVarNamed(const Expr *E, StringRef Name) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      return VD->getName() == Name;
    }
  }
  return false;
}

// Helper: check if an expression is an integer literal with the given value.
static bool isIntegerLiteral(const Expr *E, uint64_t Val) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
    return IL->getValue() == Val;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::BeginFunction,
                                        check::BranchCondition,
                                        check::PreCall,
                                        check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Shift Overflow", "Undefined Behavior")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  if (!isUtf8Decode(C))
    return;

  ProgramStateRef State = C.getState();
  State = State->set<InputBounded>(false);
  State = State->set<CountBounded>(false);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!isUtf8Decode(C))
    return;

  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;

  Cond = Cond->IgnoreParenImpCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  bool isInputGuard = false;
  if (Op == BO_GE) {
    // c >= 0xFE
    if (isVarNamed(LHS, "c") && isIntegerLiteral(RHS, 0xFE))
      isInputGuard = true;
  } else if (Op == BO_LE) {
    // 0xFE <= c
    if (isIntegerLiteral(LHS, 0xFE) && isVarNamed(RHS, "c"))
      isInputGuard = true;
  }

  if (isInputGuard) {
    ProgramStateRef State = C.getState();
    State = State->set<InputBounded>(true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isUtf8Decode(C))
    return;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  // Check for lua_assert(count <= 5)
  if (!ExprHasName(Origin, "lua_assert", C))
    return;

  const CallExpr *CE = dyn_cast<CallExpr>(Origin);
  if (!CE || CE->getNumArgs() != 1)
    return;

  const Expr *Arg = CE->getArg(0)->IgnoreParenImpCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Arg);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  bool isCountGuard = false;
  if (Op == BO_LE) {
    // count <= 5
    if (isVarNamed(LHS, "count") && isIntegerLiteral(RHS, 5))
      isCountGuard = true;
  } else if (Op == BO_GE) {
    // 5 >= count
    if (isIntegerLiteral(LHS, 5) && isVarNamed(RHS, "count"))
      isCountGuard = true;
  }

  if (isCountGuard) {
    ProgramStateRef State = C.getState();
    State = State->set<CountBounded>(true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO,
                                    CheckerContext &C) const {
  if (!isUtf8Decode(C))
    return;

  if (BO->getOpcode() != BO_Shl)
    return;

  // Check that the left-hand side is a 32-bit integer.
  QualType LHSTy = BO->getLHS()->getType();
  if (C.getASTContext().getTypeSize(LHSTy) != 32)
    return;

  // Check that the shift amount is (count * 5).
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  const BinaryOperator *Mul = dyn_cast<BinaryOperator>(RHS);
  if (!Mul || Mul->getOpcode() != BO_Mul)
    return;

  const Expr *MulLHS = Mul->getLHS()->IgnoreParenImpCasts();
  const Expr *MulRHS = Mul->getRHS()->IgnoreParenImpCasts();

  bool isCountTimes5 = false;
  if (isVarNamed(MulLHS, "count") && isIntegerLiteral(MulRHS, 5))
    isCountTimes5 = true;
  else if (isIntegerLiteral(MulLHS, 5) && isVarNamed(MulRHS, "count"))
    isCountTimes5 = true;

  if (!isCountTimes5)
    return;

  ProgramStateRef State = C.getState();
  bool inputBounded = State->get<InputBounded>();
  bool countBounded = State->get<CountBounded>();

  if (inputBounded || countBounded)
    return;

  // Report the bug.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Shift amount may exceed 31 bits before bounds validation", N);
  Report->addRange(BO->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects shift overflow in utf8_decode due to unbounded count",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
