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
#include "clang/AST/DeclCXX.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

bool containsStmt(const Stmt *Parent, const Stmt *Child) {
  if (!Parent || !Child)
    return false;
  if (Parent == Child)
    return true;
  for (const Stmt *S : Parent->children()) {
    if (containsStmt(S, Child))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double Destruction of AlignedMutex",
                       "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  bool isNullConstant(const Expr *E, CheckerContext &C) const;
  bool isNonNullTest(const Expr *Cond, StringRef Name, CheckerContext &C) const;
  bool isNullTest(const Expr *Cond, StringRef Name, CheckerContext &C) const;
  bool isGuard(const IfStmt *IS, const Stmt *Loop, CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isNullConstant(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;
  return E->isNullPointerConstant(C.getASTContext(),
                                  Expr::NPC_ValueDependentIsNull);
}

bool SAGenTestChecker::isNonNullTest(const Expr *Cond, StringRef Name,
                                     CheckerContext &C) const {
  if (!Cond)
    return false;
  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_NE) {
      if (isNullConstant(BO->getLHS(), C) &&
          ExprHasName(BO->getRHS(), Name, C))
        return true;
      if (isNullConstant(BO->getRHS(), C) &&
          ExprHasName(BO->getLHS(), Name, C))
        return true;
    }
    return false;
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot)
      return false;
    return ExprHasName(Cond, Name, C);
  }

  // Boolean test, e.g. if (cache_mutex_storage_)
  return ExprHasName(Cond, Name, C);
}

bool SAGenTestChecker::isNullTest(const Expr *Cond, StringRef Name,
                                  CheckerContext &C) const {
  if (!Cond)
    return false;
  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ) {
      if (isNullConstant(BO->getLHS(), C) &&
          ExprHasName(BO->getRHS(), Name, C))
        return true;
      if (isNullConstant(BO->getRHS(), C) &&
          ExprHasName(BO->getLHS(), Name, C))
        return true;
    }
    return false;
  }

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      return ExprHasName(Sub, Name, C);
    }
    return false;
  }

  return false;
}

bool SAGenTestChecker::isGuard(const IfStmt *IS, const Stmt *Loop,
                               CheckerContext &C) const {
  if (!IS || !Loop)
    return false;

  const Expr *Cond = IS->getCond();
  if (!Cond)
    return false;

  bool InThen = IS->getThen() && containsStmt(IS->getThen(), Loop);
  bool InElse = IS->getElse() && containsStmt(IS->getElse(), Loop);

  if (InThen)
    return isNonNullTest(Cond, "cache_mutex_storage_", C);
  if (InElse)
    return isNullTest(Cond, "cache_mutex_storage_", C);

  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Only in DFA::~DFA().
  const auto *DD = dyn_cast<CXXDestructorDecl>(C.getLocationContext()->getDecl());
  if (!DD || DD->getNameAsString() != "~DFA")
    return;

  // Match an explicit destructor call to ~AlignedMutex().
  const auto *Dtor = dyn_cast<CXXDestructorDecl>(Call.getDecl());
  if (!Dtor || Dtor->getNameAsString() != "~AlignedMutex")
    return;

  const Expr *CE = Call.getOriginExpr();
  const auto *MCE = dyn_cast_or_null<CXXMemberCallExpr>(CE);
  if (!MCE)
    return;

  // Object must be cache_mutex_[i].
  const Expr *Obj = MCE->getImplicitObjectArgument();
  if (!Obj)
    return;
  Obj = Obj->IgnoreParenImpCasts();

  const auto *ASE = dyn_cast<ArraySubscriptExpr>(Obj);
  if (!ASE)
    return;

  const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
  const auto *ME = dyn_cast<MemberExpr>(Base);
  if (!ME)
    return;

  const ValueDecl *VD = ME->getMemberDecl();
  if (!VD || VD->getNameAsString() != "cache_mutex_")
    return;

  // Find the enclosing loop over cache_mutex_count_.
  const ForStmt *FS = findSpecificTypeInParents<ForStmt>(CE, C);
  const WhileStmt *WS = findSpecificTypeInParents<WhileStmt>(CE, C);

  const Stmt *Loop = nullptr;
  if (FS && WS) {
    if (containsStmt(FS, WS))
      Loop = WS;
    else if (containsStmt(WS, FS))
      Loop = FS;
    else
      Loop = FS; // fallback
  } else if (FS) {
    Loop = FS;
  } else if (WS) {
    Loop = WS;
  } else {
    return;
  }

  const Expr *LoopCond = nullptr;
  if (const auto *F = dyn_cast<ForStmt>(Loop))
    LoopCond = F->getCond();
  else if (const auto *W = dyn_cast<WhileStmt>(Loop))
    LoopCond = W->getCond();

  if (!LoopCond || !ExprHasName(LoopCond, "cache_mutex_count_", C))
    return;

  // Walk upward through enclosing if statements looking for a guard.
  const Stmt *Cur = Loop;
  while (true) {
    const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Cur, C);
    if (!IS)
      break;
    if (isGuard(IS, Loop, C))
      return; // Guarded, no bug.
    Cur = IS;
  }

  // No guard found: report.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Manual destruction of cache_mutex_ may double-destroy inline mutex", N);
  Report->addRange(CE->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing cache_mutex_storage_ guard before manual ~AlignedMutex() loop",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
