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
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track symbols returned by calls to the `untrusted_size` role.
REGISTER_SET_WITH_PROGRAMSTATE(UntrustedSizeSymbols, SymbolRef)

namespace {

static bool hasUntrustedNarrowVar(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    QualType QT = DRE->getType();
    ASTContext &AC = C.getASTContext();

    // Must be an integer type narrower than size_t.
    if (!QT->isIntegerType())
      return false;
    if (AC.getTypeSize(QT) >= AC.getTypeSize(AC.getSizeType()))
      return false;

    SVal V = C.getState()->getSVal(DRE, C.getLocationContext());
    SymbolRef Sym = V.getAsSymbol();
    if (Sym && C.getState()->contains<UntrustedSizeSymbols>(Sym))
      return true;

    return false;
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child)) {
      if (hasUntrustedNarrowVar(ChildE, C))
        return true;
    }
  }

  return false;
}

static bool isAddWithUntrustedNarrowVar(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_Add)
    return false;

  return hasUntrustedNarrowVar(E, C);
}

static bool containsRoleCall(const Stmt *S, StringRef Role) {
  if (!S)
    return false;

  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (knighter::isRole(Role, FD->getName()))
        return true;
    }
  }

  for (const Stmt *Child : S->children()) {
    if (containsRoleCall(Child, Role))
      return true;
  }

  return false;
}

class SAGenTestChecker
    : public Checker<check::PostCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow in Bounds Check",
                       "Integer Overflow")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "untrusted_size"))
    return;

  SVal Ret = Call.getReturnValue();
  SymbolRef Sym = Ret.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<UntrustedSizeSymbols>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;
  Cond = Cond->IgnoreParenImpCasts();

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GT && Op != BO_GE && Op != BO_LT && Op != BO_LE)
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();

  bool LHSMatches = isAddWithUntrustedNarrowVar(LHS, C);
  bool RHSMatches = isAddWithUntrustedNarrowVar(RHS, C);
  if (!LHSMatches && !RHSMatches)
    return;

  const IfStmt *If = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!If)
    return;

  // Make sure this is the condition of the found IfStmt.
  if (If->getCond() != Condition)
    return;

  const Stmt *Then = If->getThen();
  const Stmt *Else = If->getElse();
  if (!Then || !Else)
    return;

  bool ThenError = containsRoleCall(Then, "error_setter");
  bool ElseCopy = containsRoleCall(Else, "buffer_copy");
  bool ThenCopy = containsRoleCall(Then, "buffer_copy");
  bool ElseError = containsRoleCall(Else, "error_setter");

  // One branch must report an error, the other must perform the buffer copy.
  if (!((ThenError && ElseCopy) || (ThenCopy && ElseError)))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "integer overflow in bounds check before buffer copy", N);
  report->addRange(Cond->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in bounds checks before buffer copy",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "untrusted_size": {"names": ["Curl_read16_le"], "description": "reads a size or length value from untrusted input"},
  "buffer_copy": {"names": ["Curl_client_write"], "description": "copies data from a buffer to an output sink; its pointer and length arguments must be within bounds"},
  "error_setter": {"names": ["failf"], "description": "records or reports an error; called when a check fails"}
}
*/
