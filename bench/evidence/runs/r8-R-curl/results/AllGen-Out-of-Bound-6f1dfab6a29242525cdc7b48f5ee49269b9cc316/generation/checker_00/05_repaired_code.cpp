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
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static StringRef getCalleeName(const CallExpr *CE) {
  if (!CE)
    return StringRef();

  if (const FunctionDecl *FD = CE->getDirectCallee())
    return FD->getName();

  const Expr *Callee = CE->getCallee()->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(Callee)) {
    if (const auto *FD = dyn_cast<FunctionDecl>(DRE->getDecl()))
      return FD->getName();
    if (const IdentifierInfo *II = DRE->getDecl()->getIdentifier())
      return II->getName();
  }

  return StringRef();
}

static bool isSubstringFinderCall(const Expr *E) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  const auto *CE = dyn_cast<CallExpr>(E);
  if (!CE)
    return false;

  StringRef Name = getCalleeName(CE);
  if (Name.empty())
    return false;

  return knighter::isRole("substring_finder", Name);
}

static const VarDecl *getBaseVar(const Expr *E) {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();
  const auto *ASE = dyn_cast<ArraySubscriptExpr>(E);
  if (!ASE)
    return nullptr;

  const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(Base);
  if (!DRE)
    return nullptr;

  return dyn_cast<VarDecl>(DRE->getDecl());
}

static int getSubscriptIndex(const Expr *E) {
  if (!E)
    return -1;

  E = E->IgnoreParenImpCasts();
  const auto *ASE = dyn_cast<ArraySubscriptExpr>(E);
  if (!ASE)
    return -1;

  const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();
  if (const auto *IL = dyn_cast<IntegerLiteral>(Idx))
    return static_cast<int>(IL->getValue().getSExtValue());

  return -1;
}

static bool isCursorZeroSubscript(const Expr *E, const VarDecl *Cursor) {
  if (!E || !Cursor)
    return false;

  E = E->IgnoreParenImpCasts();
  const auto *ASE = dyn_cast<ArraySubscriptExpr>(E);
  if (!ASE)
    return false;

  const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(Base);
  if (!DRE || DRE->getDecl() != Cursor)
    return false;

  const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();
  if (const auto *IL = dyn_cast<IntegerLiteral>(Idx))
    return IL->getValue() == 0;

  return false;
}

static bool isDeclRefTo(const Expr *E, const VarDecl *V) {
  if (!E || !V)
    return false;

  E = E->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  return DRE && DRE->getDecl() == V;
}

static bool isIncrementOf(const Stmt *S, const VarDecl *V) {
  if (!S || !V)
    return false;

  if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc)
      return isDeclRefTo(UO->getSubExpr(), V);
  }

  if (const auto *CAO = dyn_cast<CompoundAssignOperator>(S)) {
    if (CAO->getOpcode() == BO_AddAssign) {
      const Expr *RHS = CAO->getRHS()->IgnoreParenImpCasts();
      if (const auto *IL = dyn_cast<IntegerLiteral>(RHS)) {
        if (IL->getValue() == 1)
          return isDeclRefTo(CAO->getLHS(), V);
      }
    }
  }

  return false;
}

static void collectCurrentByteVars(const CompoundStmt *Block,
                                   const IfStmt *IS,
                                   const VarDecl *Cursor,
                                   SmallVectorImpl<const VarDecl *> &Out) {
  if (!Block || !IS || !Cursor)
    return;

  for (const Stmt *S : Block->body()) {
    if (S == IS)
      break;

    if (const auto *DS = dyn_cast<DeclStmt>(S)) {
      for (const Decl *D : DS->decls()) {
        const auto *VD = dyn_cast<VarDecl>(D);
        if (!VD || !VD->hasInit())
          continue;
        if (isCursorZeroSubscript(VD->getInit(), Cursor))
          Out.push_back(VD);
      }
      continue;
    }

    const auto *BO = dyn_cast<BinaryOperator>(S);
    if (!BO || BO->getOpcode() != BO_Assign)
      continue;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

    if (!isCursorZeroSubscript(RHS, Cursor))
      continue;

    if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
        Out.push_back(VD);
    }
  }
}

static bool isCursorAfterDelimiter(const VarDecl *V,
                                   const IfStmt *IS,
                                   CheckerContext &C) {
  if (!V || !IS)
    return false;

  if (!V->hasInit())
    return false;

  if (!isSubstringFinderCall(V->getInit()))
    return false;

  const CompoundStmt *Block = findSpecificTypeInParents<CompoundStmt>(IS, C);
  if (!Block)
    return false;

  for (const Stmt *S : Block->body()) {
    if (S == IS)
      break;
    if (isIncrementOf(S, V))
      return true;
  }

  return false;
}

static bool isCurrentByteVar(const Expr *E,
                             ArrayRef<const VarDecl *> CurrentVars) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  if (!DRE)
    return false;

  const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return false;

  for (const VarDecl *V : CurrentVars) {
    if (V == VD)
      return true;
  }

  return false;
}

static bool isNullTerminator(const Expr *E) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const auto *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue() == 0;

  if (const auto *CL = dyn_cast<CharacterLiteral>(E))
    return CL->getValue() == 0;

  return false;
}

static bool isGuardExpr(const Expr *E,
                        const VarDecl *Cursor,
                        ArrayRef<const VarDecl *> CurrentVars) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (isCurrentByteVar(E, CurrentVars))
    return true;

  if (isCursorZeroSubscript(E, Cursor))
    return true;

  const auto *BO = dyn_cast<BinaryOperator>(E);
  if (!BO || BO->getOpcode() != BO_NE)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

  const bool LHSIsCurrent =
      isCurrentByteVar(LHS, CurrentVars) || isCursorZeroSubscript(LHS, Cursor);
  const bool RHSIsCurrent =
      isCurrentByteVar(RHS, CurrentVars) || isCursorZeroSubscript(RHS, Cursor);

  return (LHSIsCurrent && isNullTerminator(RHS)) ||
         (RHSIsCurrent && isNullTerminator(LHS));
}

static const Expr *getFirstAndOperand(const Expr *E) {
  if (!E)
    return nullptr;

  E = E->IgnoreParenImpCasts();

  if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd)
      return getFirstAndOperand(BO->getLHS());
  }

  return E;
}

static bool hasNonTerminatorGuard(const Expr *Cond,
                                  const VarDecl *Cursor,
                                  ArrayRef<const VarDecl *> CurrentVars) {
  const Expr *First = getFirstAndOperand(Cond);
  return isGuardExpr(First, Cursor, CurrentVars);
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing non-terminator guard", "CWE-125")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

static bool detectBug(const Stmt *S,
                      const IfStmt *IS,
                      const Expr *Cond,
                      CheckerContext &C,
                      BugType &BT) {
  if (!S)
    return false;

  if (const auto *ASE = dyn_cast<ArraySubscriptExpr>(S)) {
    const int Idx = getSubscriptIndex(ASE);
    if (Idx > 0) {
      const VarDecl *Cursor = getBaseVar(ASE);
      if (Cursor && isCursorAfterDelimiter(Cursor, IS, C)) {
        SmallVector<const VarDecl *, 4> CurrentVars;
        if (const CompoundStmt *Block =
                findSpecificTypeInParents<CompoundStmt>(IS, C))
          collectCurrentByteVars(Block, IS, Cursor, CurrentVars);

        if (!hasNonTerminatorGuard(Cond, Cursor, CurrentVars)) {
          if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
            auto R = std::make_unique<PathSensitiveBugReport>(
                BT,
                "Missing non-terminator guard before lookahead after delimiter",
                N);
            R->addRange(S->getSourceRange());
            C.emitReport(std::move(R));
          }
          return true;
        }
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (detectBug(Child, IS, Cond, C, BT))
      return true;
  }

  return false;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS)
    return;

  const Expr *Cond = IS->getCond();
  if (!Cond)
    return;

  detectBug(Cond, IS, Cond, C, *BT);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing non-terminator guard before fixed-offset lookahead after a delimiter",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "substring_finder": {"names": ["strchr"], "description": "function that searches a string for a delimiter and returns a pointer to it or NULL"}
}
*/
