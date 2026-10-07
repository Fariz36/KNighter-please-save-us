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

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Strip parentheses and implicit casts.
static const Expr *strip(const Expr *E) {
  if (!E)
    return nullptr;
  return E->IgnoreParenImpCasts();
}

// Structural comparison of expressions.
static bool sameExpr(const Expr *A, const Expr *B) {
  A = strip(A);
  B = strip(B);
  if (!A || !B)
    return false;
  if (A == B)
    return true;

  if (const DeclRefExpr *DA = dyn_cast<DeclRefExpr>(A)) {
    if (const DeclRefExpr *DB = dyn_cast<DeclRefExpr>(B)) {
      return DA->getDecl() == DB->getDecl();
    }
  }

  if (const MemberExpr *MA = dyn_cast<MemberExpr>(A)) {
    if (const MemberExpr *MB = dyn_cast<MemberExpr>(B)) {
      return MA->getMemberDecl() == MB->getMemberDecl() &&
             sameExpr(MA->getBase(), MB->getBase());
    }
  }

  return false;
}

// Check whether an expression is a reference to a specific variable.
static bool isDeclRefToVar(const Expr *E, const VarDecl *VD) {
  E = strip(E);
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == VD;
  }
  return false;
}

// Get the underlying ValueDecl of an expression.
static const ValueDecl *getUnderlyingValueDecl(const Expr *E) {
  E = strip(E);
  if (!E)
    return nullptr;
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E))
    return DRE->getDecl();
  if (const MemberExpr *ME = dyn_cast<MemberExpr>(E))
    return ME->getMemberDecl();
  return nullptr;
}

// Check if a CallExpr matches a role by callee name.
static bool callMatchesRole(const CallExpr *CE, StringRef Role) {
  if (!CE)
    return false;
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    return knighter::isRole(Role, FD->getName());
  }
  return false;
}

// Check if a CallExpr has an argument structurally equal to Arg.
static bool callHasArg(const CallExpr *CE, const Expr *Arg) {
  if (!CE || !Arg)
    return false;
  for (const Expr *A : CE->arguments()) {
    if (sameExpr(A, Arg))
      return true;
  }
  return false;
}

// Recursively search for a CallExpr of the given role that uses RequiredArg.
static bool containsCallWithRole(const Stmt *S, StringRef Role,
                                 const Expr *RequiredArg) {
  if (!S)
    return false;

  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (callMatchesRole(CE, Role) && callHasArg(CE, RequiredArg))
      return true;
  }

  for (const Stmt *Child : S->children()) {
    if (containsCallWithRole(Child, Role, RequiredArg))
      return true;
  }
  return false;
}

// Recursively search for an allocator call anywhere in S.
static bool containsAllocatorCall(const Stmt *S) {
  if (!S)
    return false;

  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (callMatchesRole(CE, "allocator"))
      return true;
  }

  for (const Stmt *Child : S->children()) {
    if (containsAllocatorCall(Child))
      return true;
  }
  return false;
}

// Recursively search for an assignment to SourceVD from an allocator.
static bool assignsSourceFromAllocator(const Stmt *S, const VarDecl *SourceVD) {
  if (!S || !SourceVD)
    return false;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp() && isDeclRefToVar(BO->getLHS(), SourceVD)) {
      if (containsAllocatorCall(BO->getRHS()))
        return true;
    }
  }

  for (const Stmt *Child : S->children()) {
    if (assignsSourceFromAllocator(Child, SourceVD))
      return true;
  }
  return false;
}

// Check if the then branch contains the ownership transfer.
static bool containsTransfer(const Stmt *S, const Expr *Source,
                             const Expr *Receiver) {
  if (!S || !Source || !Receiver)
    return false;

  // Case 1: a call with role ownership_transfer using both Source and Receiver.
  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (callMatchesRole(CE, "ownership_transfer") &&
        callHasArg(CE, Source) && callHasArg(CE, Receiver)) {
      return true;
    }
  }

  // Case 2: assignment to Receiver whose RHS contains such a call using Source.
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp() && sameExpr(BO->getLHS(), Receiver)) {
      if (containsCallWithRole(BO->getRHS(), "ownership_transfer", Source)) {
        return true;
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (containsTransfer(Child, Source, Receiver))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Missing deallocator on ownership-transfer failure path",
                       "Memory Leak")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &Ctx) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &Ctx) const {
  if (!Condition)
    return;

  // Normalize condition: strip parentheses and implicit casts.
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;
  Cond = strip(Cond);

  // Require logical AND.
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO || BO->getOpcode() != BO_LAnd)
    return;

  const Expr *LHS = strip(BO->getLHS());
  const Expr *RHS = strip(BO->getRHS());
  if (!LHS || !RHS)
    return;

  // Find enclosing IfStmt.
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, Ctx);
  if (!IS)
    return;

  // Identify receiver operand.
  const ValueDecl *LHSDecl = getUnderlyingValueDecl(LHS);
  const ValueDecl *RHSDecl = getUnderlyingValueDecl(RHS);

  bool LHSIsReceiver =
      LHSDecl && knighter::declIsRole(LHSDecl, "receiver");
  bool RHSIsReceiver =
      RHSDecl && knighter::declIsRole(RHSDecl, "receiver");

  if (LHSIsReceiver == RHSIsReceiver)
    return; // exactly one must be receiver

  const Expr *Receiver = LHSIsReceiver ? LHS : RHS;
  const Expr *Source = LHSIsReceiver ? RHS : LHS;

  // Source must be a DeclRefExpr to a VarDecl.
  const DeclRefExpr *SourceDRE = dyn_cast<DeclRefExpr>(strip(Source));
  if (!SourceDRE)
    return;
  const VarDecl *SourceVD = dyn_cast<VarDecl>(SourceDRE->getDecl());
  if (!SourceVD)
    return;

  // Verify that SourceVD is allocated/duplicated.
  const Decl *CurDecl = Ctx.getCurrentAnalysisDeclContext()->getDecl();
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(CurDecl);
  if (!FD || !FD->hasBody())
    return;
  const Stmt *Body = FD->getBody();
  if (!assignsSourceFromAllocator(Body, SourceVD))
    return;

  // Inspect then branch for ownership transfer.
  const Stmt *Then = IS->getThen();
  if (!containsTransfer(Then, Source, Receiver))
    return;

  // Inspect else branch for deallocator.
  const Stmt *Else = IS->getElse();
  bool hasDeallocator =
      Else && containsCallWithRole(Else, "deallocator", Source);
  if (hasDeallocator)
    return;

  // Report missing deallocator.
  ExplodedNode *N = Ctx.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing deallocator on ownership-transfer failure path", N);
  Report->addRange(IS->getSourceRange());
  Ctx.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing deallocator on the failure path of a conditional "
      "ownership transfer",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {"names": ["sqlite3SrcListDup", "sqlite3SrcListAppendFromTerm", "sqlite3SelectNew"], "description": "function that allocates or duplicates a resource and returns ownership to the caller"},
  "ownership_transfer": {"names": ["sqlite3SrcListAppendList"], "description": "function that transfers ownership of a resource into a receiver container"},
  "receiver": {"names": ["pSrc"], "description": "field or variable that receives ownership of the transferred resource"},
  "deallocator": {"names": ["sqlite3SrcListDelete"], "description": "function that frees a resource"},
  "null_on_failure": {"names": ["pSrc"], "description": "field or variable that may be NULL on allocation failure and cause the transfer to be skipped"}
}
*/
