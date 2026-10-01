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
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Maps the memory region of the token text (arg0 of getConstraintToken)
// to the memory region of the token type variable (arg1 of getConstraintToken).
REGISTER_MAP_WITH_PROGRAMSTATE(TokenTextToTypeRegion, const MemRegion *, const MemRegion *)
// Marks a token type variable region as having been checked against TK_ILLEGAL.
REGISTER_MAP_WITH_PROGRAMSTATE(TypeRegionChecked, const MemRegion *, bool)

namespace {

class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing TK_ILLEGAL check before sqlite3Dequote()",
                       "SQLite Fuzzer Bug")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  const MemRegion *getBaseRegionOfArg(const Expr *E, CheckerContext &C) const;
  bool argRefersToRegion(const Expr *E, const MemRegion *Region,
                         CheckerContext &C) const;
  void reportMissingCheck(const CallEvent &Call, CheckerContext &C) const;
};

/// Helper: get the base MemRegion for an expression, or nullptr.
const MemRegion *SAGenTestChecker::getBaseRegionOfArg(const Expr *E,
                                                      CheckerContext &C) const {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

/// Helper: check whether an expression references the given MemRegion.
/// This handles DeclRefExpr, and also follows implicit casts/parens.
bool SAGenTestChecker::argRefersToRegion(const Expr *E, const MemRegion *Region,
                                         CheckerContext &C) const {
  if (!E || !Region)
    return false;
  const Expr *Inner = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Inner)) {
    const MemRegion *R = getMemRegionFromExpr(DRE, C);
    if (R) {
      R = R->getBaseRegion();
      if (R && R == Region)
        return true;
    }
  }
  // Fallback: compare via SVal resolution.
  const MemRegion *R = getBaseRegionOfArg(E, C);
  return R && R == Region;
}

/// checkPostCall: detect getConstraintToken() call and record relationship
/// between the token text buffer and the token type variable.
void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "getConstraintToken", C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  const MemRegion *TextReg = getBaseRegionOfArg(Call.getArgExpr(0), C);
  const MemRegion *TypeReg = getBaseRegionOfArg(Call.getArgExpr(1), C);
  if (!TextReg || !TypeReg)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<TokenTextToTypeRegion>(TextReg, TypeReg);
  // New token type was produced - must be rechecked against TK_ILLEGAL.
  State = State->set<TypeRegionChecked>(TypeReg, false);
  C.addTransition(State);
}

/// checkBranchCondition: detect `t == TK_ILLEGAL` / `t != TK_ILLEGAL` and
/// mark the corresponding token type variable as checked.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  CondE = CondE->IgnoreParenCasts();

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_EQ && Op != BO_NE)
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

  // Interesting side: the variable. Other side: TK_ILLEGAL.
  const Expr *VarExpr = nullptr;
  const Expr *ConstExpr = nullptr;

  if (ExprHasName(LHS, "TK_ILLEGAL", C)) {
    ConstExpr = LHS;
    VarExpr = RHS;
  } else if (ExprHasName(RHS, "TK_ILLEGAL", C)) {
    ConstExpr = RHS;
    VarExpr = LHS;
  } else {
    // Try evaluating the token type expression to an int and see if it
    // matches TK_ILLEGAL value. Since we don't have direct TK_ILLEGAL
    // numeric value knowledge here, rely on the name check fallback.
    return;
  }
  (void)ConstExpr;

  if (!VarExpr)
    return;

  const MemRegion *VarReg = getBaseRegionOfArg(VarExpr, C);
  if (!VarReg)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *const *MappedType =
      State->get<TokenTextToTypeRegion>(VarReg);
  // We only care if this variable is (or maps to) a tracked token type.
  const MemRegion *TypeReg = MappedType ? *MappedType : VarReg;

  State = State->set<TypeRegionChecked>(TypeReg, true);
  // Also mark the directly-referenced region (in case they differ).
  State = State->set<TypeRegionChecked>(VarReg, true);
  C.addTransition(State);
}

/// checkPreCall: detect quotedCompare() call and verify that the token type
/// paired with the token text was previously checked against TK_ILLEGAL.
void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "quotedCompare", C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  ProgramStateRef State = C.getState();

  // Find any argument that corresponds to a tracked token text region.
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    const MemRegion *ArgReg = getBaseRegionOfArg(ArgE, C);
    if (!ArgReg)
      continue;

    const MemRegion *const *TypeRegPtr =
        State->get<TokenTextToTypeRegion>(ArgReg);
    if (!TypeRegPtr)
      continue;
    const MemRegion *TypeReg = *TypeRegPtr;

    // We found a token text whose type variable we are tracking.
    // Determine whether the token type is safe:
    //  (a) The type variable region is checked against TK_ILLEGAL.
    //  (b) The token type variable is passed as an argument to this call.
    bool Safe = false;

    const bool *Checked = State->get<TypeRegionChecked>(TypeReg);
    if (Checked && *Checked)
      Safe = true;

    if (!Safe) {
      for (unsigned j = 0; j < Call.getNumArgs(); ++j) {
        const Expr *JE = Call.getArgExpr(j);
        if (argRefersToRegion(JE, TypeReg, C)) {
          Safe = true;
          break;
        }
      }
    }

    if (!Safe) {
      reportMissingCheck(Call, C);
      return; // report once
    }
  }
}

void SAGenTestChecker::reportMissingCheck(const CallEvent &Call,
                                          CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing TK_ILLEGAL check before sqlite3Dequote()", N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing TK_ILLEGAL check before sqlite3Dequote() in ALTER TABLE "
      "DROP CONSTRAINT",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
