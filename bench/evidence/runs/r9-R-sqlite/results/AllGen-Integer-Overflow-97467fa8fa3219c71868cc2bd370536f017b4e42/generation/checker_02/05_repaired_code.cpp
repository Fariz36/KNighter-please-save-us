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
#include "knighter/roles.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool stmtReferencesVar(const Stmt *S, const VarDecl *VD) {
  if (!S || !VD)
    return false;

  if (const Expr *E = dyn_cast<Expr>(S)) {
    const Expr *Cleaned = E->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Cleaned)) {
      if (DRE->getDecl() == VD)
        return true;
    }
  }

  for (const Stmt *Child : S->children()) {
    if (stmtReferencesVar(Child, VD))
      return true;
  }
  return false;
}

static bool containsMultiplication(const Stmt *S) {
  if (!S)
    return false;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Mul)
      return true;
  }

  for (const Stmt *Child : S->children()) {
    if (containsMultiplication(Child))
      return true;
  }
  return false;
}

static const CompoundAssignOperator *
findOverflowAccumulation(const Stmt *S, const VarDecl *VD,
                         const SourceManager &SM, SourceLocation BeforeLoc) {
  if (!S || !VD)
    return nullptr;

  if (const CompoundAssignOperator *CAO =
          dyn_cast<CompoundAssignOperator>(S)) {
    if (CAO->getOpcode() == BO_AddAssign) {
      const Expr *LHS = CAO->getLHS()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (DRE->getDecl() == VD && containsMultiplication(CAO->getRHS())) {
          if (BeforeLoc.isValid() && CAO->getBeginLoc().isValid() &&
              SM.isBeforeInTranslationUnit(CAO->getBeginLoc(), BeforeLoc)) {
            return CAO;
          }
        }
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (const CompoundAssignOperator *Res =
            findOverflowAccumulation(Child, VD, SM, BeforeLoc)) {
      return Res;
    }
  }
  return nullptr;
}

static bool containsEarlyGuard(const Stmt *S, const VarDecl *VD) {
  if (!S || !VD)
    return false;

  if (const IfStmt *IS = dyn_cast<IfStmt>(S)) {
    if (const Expr *Cond = IS->getCond()) {
      const Expr *Cleaned = Cond->IgnoreParenImpCasts();
      if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cleaned)) {
        if (BO->getOpcode() == BO_GT || BO->getOpcode() == BO_GE) {
          if (stmtReferencesVar(BO->getLHS(), VD) ||
              stmtReferencesVar(BO->getRHS(), VD)) {
            return true;
          }
        }
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (containsEarlyGuard(Child, VD))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow", "Memory Write")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "memory_writer"))
    return;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;

  const CallExpr *CE = dyn_cast<CallExpr>(Origin);
  if (!CE || CE->getNumArgs() < 3)
    return;

  const Expr *SizeArg = CE->getArg(2);
  if (!SizeArg)
    return;

  SizeArg = SizeArg->IgnoreParenImpCasts();
  const DeclRefExpr *LenDRE = dyn_cast<DeclRefExpr>(SizeArg);
  if (!LenDRE)
    return;

  const VarDecl *LenVD = dyn_cast<VarDecl>(LenDRE->getDecl());
  if (!LenVD)
    return;

  QualType QT = LenVD->getType();
  if (!QT->isSignedIntegerType())
    return;
  if (C.getASTContext().getTypeSize(QT) >= 64)
    return;

  const LocationContext *LC = Call.getLocationContext();
  if (!LC)
    return;

  const Decl *D = LC->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || !knighter::declIsRole(FD, "parser_input"))
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  const SourceManager &SM = C.getSourceManager();
  SourceLocation CallLoc = Origin->getBeginLoc();
  const CompoundAssignOperator *CAO =
      findOverflowAccumulation(Body, LenVD, SM, CallLoc);
  if (!CAO)
    return;

  const WhileStmt *WS = findSpecificTypeInParents<WhileStmt>(CAO, C);
  const ForStmt *FS = findSpecificTypeInParents<ForStmt>(CAO, C);
  const DoStmt *DS = findSpecificTypeInParents<DoStmt>(CAO, C);

  const Stmt *LoopBody = nullptr;
  if (WS)
    LoopBody = WS->getBody();
  else if (FS)
    LoopBody = FS->getBody();
  else if (DS)
    LoopBody = DS->getBody();

  if (!LoopBody)
    return;

  if (containsEarlyGuard(LoopBody, LenVD))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Possible integer overflow in decoded length before memory_writer size "
      "argument",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects possible integer overflow in a decoded length before a "
      "memory_writer size argument",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["kvvfsDecode"], "description": "function that parses or decodes untrusted input; its input can drive computed lengths or values"},
  "memory_writer": {"names": ["memset"], "description": "writes bytes to a destination using a length/count argument; the count must not be overflowed or negative"}
}
*/
