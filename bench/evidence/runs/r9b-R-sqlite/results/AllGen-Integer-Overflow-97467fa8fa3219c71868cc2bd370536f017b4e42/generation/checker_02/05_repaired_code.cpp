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
#include "clang/AST/Stmt.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/OperationKinds.h"
#include "llvm/ADT/APSInt.h"
#include "knighter/roles.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(OverflowSizeMap, const VarDecl *, bool)

namespace {

bool isSignedIntLessThan64(const VarDecl *VD, ASTContext &Ctx) {
  if (!VD)
    return false;
  QualType QT = VD->getType();
  if (!QT->isSignedIntegerType())
    return false;
  unsigned Width = Ctx.getIntWidth(QT);
  return Width > 0 && Width < 64;
}

bool isDREToVar(const Expr *E, const VarDecl *VD) {
  if (!E || !VD)
    return false;
  E = E->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
  return DRE && DRE->getDecl() == VD;
}

bool isRelationalOp(BinaryOperatorKind Op) {
  return Op == BO_GT || Op == BO_GE || Op == BO_LT || Op == BO_LE ||
         Op == BO_EQ || Op == BO_NE;
}

class MulOperandFinder : public RecursiveASTVisitor<MulOperandFinder> {
public:
  const VarDecl *MultVar = nullptr;

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Mul)
      return true;

    for (int I = 0; I < 2; ++I) {
      const Expr *Op = (I == 0) ? BO->getLHS() : BO->getRHS();
      if (const DeclRefExpr *DRE =
              dyn_cast<DeclRefExpr>(Op->IgnoreParenImpCasts())) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          MultVar = VD;
          return false;
        }
      }
    }
    return true;
  }
};

class MulConstantFinder : public RecursiveASTVisitor<MulConstantFinder> {
  const VarDecl *MultVar;
  CheckerContext &C;

public:
  llvm::APSInt Value;
  bool Found = false;

  MulConstantFinder(const VarDecl *MV, CheckerContext &Ctx)
      : MultVar(MV), C(Ctx) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Mul)
      return true;

    for (int I = 0; I < 2; ++I) {
      const Expr *Op = (I == 0) ? BO->getLHS() : BO->getRHS();
      if (isDREToVar(Op, MultVar)) {
        const Expr *Other = (I == 0) ? BO->getRHS() : BO->getLHS();
        llvm::APSInt EvalRes;
        if (EvaluateExprToInt(EvalRes, Other->IgnoreParenImpCasts(), C)) {
          Value = EvalRes;
          Found = true;
          return false;
        }
      }
    }
    return true;
  }
};

class MultUpdateFinder : public RecursiveASTVisitor<MultUpdateFinder> {
  const VarDecl *MultVar;
  CheckerContext &C;

public:
  bool Found = false;

  MultUpdateFinder(const VarDecl *MV, CheckerContext &Ctx)
      : MultVar(MV), C(Ctx) {}

  bool VisitCompoundAssignOperator(CompoundAssignOperator *CO) {
    if (CO->getOpcode() != BO_MulAssign)
      return true;
    if (!isDREToVar(CO->getLHS(), MultVar))
      return true;

    llvm::APSInt EvalRes;
    if (EvaluateExprToInt(EvalRes, CO->getRHS()->IgnoreParenImpCasts(), C)) {
      if (EvalRes > 1) {
        Found = true;
        return false;
      }
    }
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Assign)
      return true;
    if (!isDREToVar(BO->getLHS(), MultVar))
      return true;

    MulConstantFinder Finder(MultVar, C);
    Finder.TraverseStmt(BO->getRHS());
    if (Finder.Found && Finder.Value > 1) {
      Found = true;
      return false;
    }
    return true;
  }
};

class RelationalVarFinder : public RecursiveASTVisitor<RelationalVarFinder> {
  const VarDecl *VD;

public:
  bool Found = false;

  RelationalVarFinder(const VarDecl *V) : VD(V) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (!isRelationalOp(BO->getOpcode()))
      return true;
    if (isDREToVar(BO->getLHS(), VD) || isDREToVar(BO->getRHS(), VD)) {
      Found = true;
      return false;
    }
    return true;
  }
};

bool containsReturnOrBreak(const Stmt *S) {
  if (!S)
    return false;
  return findSpecificTypeInChildren<ReturnStmt>(S) != nullptr ||
         findSpecificTypeInChildren<BreakStmt>(S) != nullptr;
}

class OverflowGuardFinder : public RecursiveASTVisitor<OverflowGuardFinder> {
  const VarDecl *SizeVar;

public:
  bool Found = false;

  OverflowGuardFinder(const VarDecl *VD) : SizeVar(VD) {}

  bool VisitIfStmt(IfStmt *IS) {
    if (!IS || !IS->getCond())
      return true;

    RelationalVarFinder RVF(SizeVar);
    RVF.TraverseStmt(IS->getCond());
    if (RVF.Found) {
      if (containsReturnOrBreak(IS->getThen()) ||
          (IS->getElse() && containsReturnOrBreak(IS->getElse()))) {
        Found = true;
        return false;
      }
    }
    return true;
  }
};

const Stmt *getEnclosingLoopBody(const Stmt *S, CheckerContext &C) {
  if (const WhileStmt *WS = findSpecificTypeInParents<WhileStmt>(S, C))
    return WS->getBody();
  if (const ForStmt *FS = findSpecificTypeInParents<ForStmt>(S, C))
    return FS->getBody();
  if (const DoStmt *DS = findSpecificTypeInParents<DoStmt>(S, C))
    return DS->getBody();
  return nullptr;
}

bool hasExponentialMultiplierUpdate(const Stmt *LoopBody,
                                    const VarDecl *MultVar,
                                    CheckerContext &C) {
  if (!LoopBody || !MultVar)
    return false;
  MultUpdateFinder Finder(MultVar, C);
  Finder.TraverseStmt(const_cast<Stmt *>(LoopBody));
  return Finder.Found;
}

bool hasOverflowGuard(const Stmt *LoopBody, const VarDecl *SizeVar) {
  if (!LoopBody || !SizeVar)
    return false;
  OverflowGuardFinder Finder(SizeVar);
  Finder.TraverseStmt(const_cast<Stmt *>(LoopBody));
  return Finder.Found;
}

class SAGenTestChecker
    : public Checker<check::PreStmt<CompoundAssignOperator>, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer overflow in untrusted size",
                       "Memory Error")) {}

  void checkPreStmt(const CompoundAssignOperator *CO, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPreStmt(const CompoundAssignOperator *CO,
                                    CheckerContext &C) const {
  if (!CO)
    return;

  const Decl *D = C.getCurrentAnalysisDeclContext()
                      ? C.getCurrentAnalysisDeclContext()->getDecl()
                      : nullptr;
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || !knighter::declIsRole(FD, "parser_input"))
    return;

  if (CO->getOpcode() != BO_AddAssign)
    return;

  const Expr *LHS = CO->getLHS()->IgnoreParenImpCasts();
  const DeclRefExpr *LHSDRE = dyn_cast<DeclRefExpr>(LHS);
  if (!LHSDRE)
    return;
  const VarDecl *SizeVar = dyn_cast<VarDecl>(LHSDRE->getDecl());
  if (!SizeVar || !SizeVar->isLocalVarDecl())
    return;
  if (!isSignedIntLessThan64(SizeVar, C.getASTContext()))
    return;

  MulOperandFinder MOF;
  MOF.TraverseStmt(CO->getRHS());
  const VarDecl *MultVar = MOF.MultVar;
  if (!MultVar || !MultVar->isLocalVarDecl())
    return;
  if (!isSignedIntLessThan64(MultVar, C.getASTContext()))
    return;

  const Stmt *LoopBody = getEnclosingLoopBody(CO, C);
  if (!LoopBody)
    return;

  if (!hasExponentialMultiplierUpdate(LoopBody, MultVar, C))
    return;

  if (hasOverflowGuard(LoopBody, SizeVar))
    return;

  ProgramStateRef State = C.getState();
  if (State->get<OverflowSizeMap>(SizeVar))
    return;
  State = State->set<OverflowSizeMap>(SizeVar, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "init"))
    return;
  if (Call.getNumArgs() < 3)
    return;

  const Expr *SizeArg = Call.getArgExpr(2);
  if (!SizeArg)
    return;
  SizeArg = SizeArg->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(SizeArg);
  if (!DRE)
    return;
  const VarDecl *SizeVar = dyn_cast<VarDecl>(DRE->getDecl());
  if (!SizeVar)
    return;

  ProgramStateRef State = C.getState();
  const bool *Flag = State->get<OverflowSizeMap>(SizeVar);
  if (!Flag || !*Flag)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Integer overflow in untrusted size used as memset length", N);
  report->addRange(SizeArg->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in an untrusted size accumulated in a loop and "
      "then used as a memory initialization length",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["kvvfsDecode"], "description": "function that decodes an untrusted encoded byte stream and may compute sizes from it"},
  "init": {"names": ["memset"], "description": "memory initialization/write function that takes a size argument and writes that many bytes"}
}
*/
