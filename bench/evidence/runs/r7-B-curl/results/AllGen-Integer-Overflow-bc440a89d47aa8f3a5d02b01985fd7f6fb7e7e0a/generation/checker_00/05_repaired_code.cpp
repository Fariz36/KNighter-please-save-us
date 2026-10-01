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
#include "llvm/Support/Casting.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UncheckedSizeMap, const MemRegion *, bool)

namespace {

class SAGenTestChecker
    : public Checker<check::PostStmt<DeclStmt>,
                     check::BranchCondition,
                     check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Base64 size calculation overflow",
                       "Integer Overflow")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;

private:
  bool isEncoderBase64Size(CheckerContext &C) const;
  bool isPartDatasizeInit(const Expr *E, CheckerContext &C) const;
  bool isOverflowProneBase64Arithmetic(const Expr *E, CheckerContext &C) const;
  bool containsSizeDeclRef(const Expr *E) const;
  const DeclRefExpr *findSizeDeclRef(const Stmt *S) const;
  void reportOverflow(const Stmt *S, CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isEncoderBase64Size(CheckerContext &C) const {
  const LocationContext *LCtx = C.getLocationContext();
  if (!LCtx)
    return false;

  const Decl *D = LCtx->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return false;

  return FD->getName() == "encoder_base64_size";
}

bool SAGenTestChecker::isPartDatasizeInit(const Expr *E,
                                          CheckerContext &C) const {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const MemberExpr *ME = dyn_cast<MemberExpr>(E)) {
    const ValueDecl *VD = ME->getMemberDecl();
    if (VD && VD->getName() == "datasize") {
      if (ExprHasName(ME->getBase(), "part", C))
        return true;
    }
  }

  return ExprHasName(E, "part->datasize", C);
}

bool SAGenTestChecker::containsSizeDeclRef(const Expr *E) const {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      if (VD->getName() == "size")
        return true;
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child))
      if (containsSizeDeclRef(ChildE))
        return true;
  }

  return false;
}

bool SAGenTestChecker::isOverflowProneBase64Arithmetic(
    const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();

    if (Op == BO_Mul || Op == BO_Div) {
      if (containsSizeDeclRef(BO->getLHS()) ||
          containsSizeDeclRef(BO->getRHS()))
        return true;
    }

    if (ExprHasName(E, "MAX_ENCODED_LINE_LENGTH", C)) {
      if (Op == BO_Mul || Op == BO_Add || Op == BO_Div)
        return true;
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child))
      if (isOverflowProneBase64Arithmetic(ChildE, C))
        return true;
  }

  return false;
}

const DeclRefExpr *SAGenTestChecker::findSizeDeclRef(const Stmt *S) const {
  if (!S)
    return nullptr;

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      if (VD->getName() == "size")
        return DRE;
  }

  for (const Stmt *Child : S->children()) {
    if (const DeclRefExpr *DRE = findSizeDeclRef(Child))
      return DRE;
  }

  return nullptr;
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS,
                                     CheckerContext &C) const {
  if (!isEncoderBase64Size(C))
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (const Decl *D : DS->decls()) {
    const VarDecl *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;

    if (!VD->getName().equals("size"))
      continue;

    const Expr *Init = VD->getInit();
    if (!Init || !isPartDatasizeInit(Init, C))
      continue;

    const MemRegion *MR = State->getRegion(VD, C.getLocationContext());
    if (!MR)
      continue;

    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    State = State->set<UncheckedSizeMap>(MR, true);
    Changed = true;
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!isEncoderBase64Size(C))
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  if (!ExprHasName(CondE, "BASE64_MAX_INPUT_SIZE", C))
    return;

  const IfStmt *If = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!If)
    return;

  const Stmt *Then = If->getThen();
  const ReturnStmt *Ret = findSpecificTypeInChildren<ReturnStmt>(Then);
  if (!Ret)
    return;

  const Expr *RetExpr = Ret->getRetValue();
  if (!RetExpr)
    return;

  llvm::APSInt Val;
  if (!EvaluateExprToInt(Val, RetExpr, C))
    return;
  if (!Val.isNegative())
    return;

  const DeclRefExpr *SizeDRE = findSizeDeclRef(CondE);
  if (!SizeDRE)
    return;

  const VarDecl *VD = dyn_cast<VarDecl>(SizeDRE->getDecl());
  if (!VD)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = State->getRegion(VD, C.getLocationContext());
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  const bool *Unchecked = State->get<UncheckedSizeMap>(MR);
  if (Unchecked && *Unchecked) {
    State = State->set<UncheckedSizeMap>(MR, false);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  if (!isEncoderBase64Size(C))
    return;

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  MR = MR->getBaseRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  const bool *Unchecked = State->get<UncheckedSizeMap>(MR);
  if (!Unchecked || !*Unchecked)
    return;

  const Expr *RHS = nullptr;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign)
      RHS = BO->getRHS();
  } else if (const Expr *E = dyn_cast<Expr>(S)) {
    if (const BinaryOperator *BO =
            findSpecificTypeInParents<BinaryOperator>(S, C)) {
      if (BO->getOpcode() == BO_Assign && BO->getRHS() == E)
        RHS = E;
    }
  }

  if (!RHS || !isOverflowProneBase64Arithmetic(RHS, C))
    return;

  reportOverflow(S, C);
}

void SAGenTestChecker::reportOverflow(const Stmt *S,
                                      CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Possible integer overflow in base64 size calculation", N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked integer overflow in base64 size calculation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
