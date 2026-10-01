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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(GitStrAllocMap, const MemRegion *, bool)

namespace {

static bool isGitStrType(QualType QT) {
  if (QT.getAsString() == "git_str")
    return true;

  QualType CT = QT.getCanonicalType();
  if (const RecordType *RT = CT->getAs<RecordType>())
    return RT->getDecl() && RT->getDecl()->getName() == "git_str";

  return false;
}

static bool isGitStrVar(const VarDecl *VD) {
  if (!VD)
    return false;
  if (!VD->isLocalVarDecl())
    return false;
  if (isa<ParmVarDecl>(VD))
    return false;

  return isGitStrType(VD->getType());
}

static const VarRegion *getGitStrArgRegion(const CallEvent &Call) {
  if (Call.getNumArgs() < 1)
    return nullptr;

  SVal Arg = Call.getArgSVal(0);
  const MemRegion *MR = Arg.getAsRegion();
  if (!MR)
    return nullptr;

  MR = MR->getBaseRegion();
  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return nullptr;

  if (!isGitStrVar(VR->getDecl()))
    return nullptr;

  return VR;
}

static bool isCallTo(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;

  if (!ExprHasName(E, Name, C))
    return false;

  if (const IdentifierInfo *II = Call.getCalleeIdentifier())
    return II->getName() == Name;

  return true;
}

static bool isAllocCall(const CallEvent &Call, CheckerContext &C) {
  return isCallTo(Call, "git_fs_path_prettify_dir", C);
}

static bool isDisposeCall(const CallEvent &Call, CheckerContext &C) {
  return isCallTo(Call, "git_str_dispose", C);
}

static bool isDetachCall(const CallEvent &Call, CheckerContext &C) {
  return isCallTo(Call, "git_str_detach", C);
}

static bool isZeroConstant(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  llvm::APSInt V;
  return EvaluateExprToInt(V, E, C) && V.isZero();
}

static bool exprIsCallTo(const Expr *E, StringRef Name, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  if (!E)
    return false;

  if (!ExprHasName(E, Name, C))
    return false;

  if (const CallExpr *CE = dyn_cast<CallExpr>(E)) {
    if (const FunctionDecl *FD = CE->getDirectCallee())
      return FD->getName() == Name;
  }

  return true;
}

static bool isPrettifyFailureReturn(const ReturnStmt *RS, CheckerContext &C) {
  if (!RS)
    return false;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(RS, C);
  if (!IS)
    return false;

  const Stmt *Then = IS->getThen();
  if (!Then || Then != RS)
    return false;

  const Expr *Cond = IS->getCond();
  if (!Cond)
    return false;

  Cond = Cond->IgnoreParens();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return false;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_LT && Op != BO_NE)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParens();
  const Expr *RHS = BO->getRHS()->IgnoreParens();

  if (Op == BO_LT) {
    return exprIsCallTo(LHS, "git_fs_path_prettify_dir", C) &&
           isZeroConstant(RHS, C);
  }

  return (exprIsCallTo(LHS, "git_fs_path_prettify_dir", C) &&
          isZeroConstant(RHS, C)) ||
         (exprIsCallTo(RHS, "git_fs_path_prettify_dir", C) &&
          isZeroConstant(LHS, C));
}

static bool isRegionInCurrentFunction(const MemRegion *MR, CheckerContext &C) {
  const VarRegion *VR = dyn_cast<VarRegion>(MR);
  if (!VR)
    return false;

  const VarDecl *VD = VR->getDecl();
  if (!VD)
    return false;

  const Decl *CurDecl = C.getLocationContext()->getDecl();
  return VD->getParentFunctionOrMethod() == Decl::castToDeclContext(CurDecl);
}

class SAGenTestChecker
    : public Checker<check::PostCall,
                     check::PreCall,
                     check::PreStmt<ReturnStmt>,
                     check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Memory leak: git_str not disposed before return",
                       "Memory Leak")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;

private:
  void reportLeak(const ReturnStmt *RS, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isAllocCall(Call, C))
    return;

  const VarRegion *VR = getGitStrArgRegion(Call);
  if (!VR)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<GitStrAllocMap>(VR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isDisposeCall(Call, C) && !isDetachCall(Call, C))
    return;

  const VarRegion *VR = getGitStrArgRegion(Call);
  if (!VR)
    return;

  ProgramStateRef State = C.getState();
  if (!State->get<GitStrAllocMap>(VR))
    return;

  State = State->remove<GitStrAllocMap>(VR);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS,
                                    CheckerContext &C) const {
  if (!RS)
    return;

  if (isPrettifyFailureReturn(RS, C))
    return;

  ProgramStateRef State = C.getState();
  for (const auto &Entry : State->get<GitStrAllocMap>()) {
    if (!Entry.second)
      continue;

    if (isRegionInCurrentFunction(Entry.first, C)) {
      reportLeak(RS, C);
      return;
    }
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS,
                                        CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  llvm::SmallVector<const MemRegion *, 8> ToRemove;

  for (const auto &Entry : State->get<GitStrAllocMap>()) {
    if (isRegionInCurrentFunction(Entry.first, C))
      ToRemove.push_back(Entry.first);
  }

  if (ToRemove.empty())
    return;

  for (const MemRegion *MR : ToRemove)
    State = State->remove<GitStrAllocMap>(MR);

  C.addTransition(State);
}

void SAGenTestChecker::reportLeak(const ReturnStmt *RS,
                                  CheckerContext &C) const {
  if (!BT)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Memory leak: git_str not disposed before return", N);

  if (RS)
    Report->addRange(RS->getSourceRange());

  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects git_str memory leaks before function returns",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
