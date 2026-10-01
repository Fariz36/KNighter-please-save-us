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
#include "clang/AST/DeclCXX.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map: tracks symbols returned by Regexp::Simplify().
// true  -> result has not been NULL-checked yet.
// false -> result has been NULL-checked.
REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedSimplifyResult, SymbolRef, bool)

namespace {

class SAGenTestChecker
    : public Checker<check::PostCall,
                     check::PreCall,
                     check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Unchecked Simplify Result",
                       "Null Dereference")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void reportUncheckedUse(const CallEvent &Call, CheckerContext &C) const;
};

// Returns true if the call is Regexp::Simplify().
static bool isRegexpSimplify(const CallEvent &Call) {
  const Decl *D = Call.getDecl();
  const auto *MD = dyn_cast_or_null<CXXMethodDecl>(D);
  if (!MD)
    return false;
  if (MD->getNameAsString() != "Simplify")
    return false;
  const CXXRecordDecl *RD = MD->getParent();
  if (!RD || RD->getNameAsString() != "Regexp")
    return false;
  return true;
}

// Extract a SymbolRef from an SVal.
static SymbolRef getSymbolFromSVal(SVal V) {
  return V.getAsSymbol();
}

// Extract a SymbolRef from an expression.
static SymbolRef getSymbolFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  SVal V = C.getState()->getSVal(E, C.getLocationContext());
  return getSymbolFromSVal(V);
}

// Extract the pointer symbol that is being NULL-checked in a condition.
static SymbolRef getNullCheckedSymbol(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();

  // Handle !expr
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      return getSymbolFromExpr(UO->getSubExpr(), C);
    }
  }

  // Handle expr == NULL, expr != NULL, expr == 0, expr != 0,
  // expr == nullptr, expr != nullptr, etc.
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      ASTContext &AC = C.getASTContext();
      bool LHSIsNull = LHS->isNullPointerConstant(
          AC, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          AC, Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && !RHSIsNull)
        return getSymbolFromExpr(RHS, C);
      if (RHSIsNull && !LHSIsNull)
        return getSymbolFromExpr(LHS, C);
    }
  }

  // Handle bare pointer condition: if (ptr)
  return getSymbolFromExpr(E, C);
}

// Returns true if the function is known to dereference its argument(s).
static bool isDerefFunction(const CallEvent &Call) {
  const IdentifierInfo *ID = Call.getCalleeIdentifier();
  if (!ID)
    return false;
  StringRef Name = ID->getName();
  return Name == "BuildInfo" || Name == "Decref" || Name == "ToString";
}

} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isRegexpSimplify(Call))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = getSymbolFromSVal(RetVal);
  if (!Sym)
    return;

  State = State->set<UncheckedSimplifyResult>(Sym, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  SymbolRef Sym = getNullCheckedSymbol(CondE, C);
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  const bool *Unchecked = State->get<UncheckedSimplifyResult>(Sym);
  if (Unchecked && *Unchecked) {
    State = State->set<UncheckedSimplifyResult>(Sym, false);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isDerefFunction(Call))
    return;

  ProgramStateRef State = C.getState();

  // Check explicit arguments.
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    SVal Arg = Call.getArgSVal(i);
    SymbolRef Sym = getSymbolFromSVal(Arg);
    if (!Sym)
      continue;
    const bool *Unchecked = State->get<UncheckedSimplifyResult>(Sym);
    if (Unchecked && *Unchecked) {
      reportUncheckedUse(Call, C);
      return;
    }
  }

  // Check implicit object argument for C++ member calls, e.g. simple->Decref().
  if (const auto *MCE = dyn_cast<CXXMemberCall>(&Call)) {
    SVal ThisVal = MCE->getCXXThisVal();
    SymbolRef Sym = getSymbolFromSVal(ThisVal);
    if (Sym) {
      const bool *Unchecked = State->get<UncheckedSimplifyResult>(Sym);
      if (Unchecked && *Unchecked) {
        reportUncheckedUse(Call, C);
        return;
      }
    }
  }
}

void SAGenTestChecker::reportUncheckedUse(const CallEvent &Call,
                                          CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unchecked Regexp::Simplify() result used before NULL check",
      N);
  report->addRange(Call.getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked Regexp::Simplify() results used before NULL check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
