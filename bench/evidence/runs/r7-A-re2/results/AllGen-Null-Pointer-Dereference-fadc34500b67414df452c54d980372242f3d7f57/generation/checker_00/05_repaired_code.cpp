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

#include "clang/AST/DeclCXX.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/StmtCXX.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_TRAIT_WITH_PROGRAMSTATE(StorageGuarded, bool)

namespace {

static bool isCacheMutexStorageNullCheck(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  auto isStorageMember = [](const Expr *e) -> bool {
    if (const auto *ME = dyn_cast<MemberExpr>(e->IgnoreParenImpCasts())) {
      if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
        return FD->getName() == "cache_mutex_storage_";
      }
    }
    return false;
  };

  // if (cache_mutex_storage_)
  if (isStorageMember(E))
    return true;

  // if (!cache_mutex_storage_)
  if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_LNot) {
      if (isStorageMember(UO->getSubExpr()))
        return true;
    }
  }

  // if (cache_mutex_storage_ == NULL) or if (cache_mutex_storage_ != NULL)
  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      auto isNull = [&](const Expr *e) -> bool {
        return e->isNullPointerConstant(C.getASTContext(),
                                        Expr::NPC_ValueDependentIsNull);
      };
      if ((isStorageMember(LHS) && isNull(RHS)) ||
          (isStorageMember(RHS) && isNull(LHS)))
        return true;
    }
  }

  return false;
}

class SAGenTestChecker : public Checker<check::BeginFunction,
                                        check::BranchCondition,
                                        check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unconditional Destructor Call",
                       "Memory Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const Decl *D = C.getLocationContext()->getDecl();
  const auto *Dtor = dyn_cast_or_null<CXXDestructorDecl>(D);
  if (!Dtor)
    return;
  const CXXRecordDecl *Parent = Dtor->getParent();
  if (!Parent || Parent->getName() != "DFA")
    return;

  ProgramStateRef State = C.getState();
  State = State->set<StorageGuarded>(false);
  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  if (isCacheMutexStorageNullCheck(CondE, C)) {
    ProgramStateRef State = C.getState();
    State = State->set<StorageGuarded>(true);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *CE = Call.getOriginExpr();
  if (!CE)
    return;

  const auto *MCE = dyn_cast<CXXMemberCallExpr>(CE);
  if (!MCE)
    return;

  const CXXMethodDecl *MD = MCE->getMethodDecl();
  if (!MD)
    return;

  const auto *Dtor = dyn_cast<CXXDestructorDecl>(MD);
  if (!Dtor)
    return;

  if (!Dtor->getParent() || Dtor->getParent()->getName() != "AlignedMutex")
    return;

  const Expr *Obj = MCE->getImplicitObjectArgument();
  if (!Obj)
    return;

  const auto *ASE = dyn_cast<ArraySubscriptExpr>(Obj->IgnoreParenImpCasts());
  if (!ASE)
    return;

  if (!ExprHasName(ASE->getBase(), "cache_mutex_", C))
    return;

  const ForStmt *FS = findSpecificTypeInParents<ForStmt>(CE, C);
  if (!FS)
    return;

  ProgramStateRef State = C.getState();
  bool Guarded = State->get<StorageGuarded>();
  if (Guarded)
    return;

  reportBug(Call, C);
}

void SAGenTestChecker::reportBug(const CallEvent &Call,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unconditional destructor call on cache_mutex_ without checking "
      "cache_mutex_storage_",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unconditional destructor calls on cache_mutex_ without "
      "checking cache_mutex_storage_",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
