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

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static const Expr *strip(const Expr *E) {
  while (E) {
    if (const auto *PE = dyn_cast<ParenExpr>(E)) {
      E = PE->getSubExpr();
    } else if (const auto *ICE = dyn_cast<ImplicitCastExpr>(E)) {
      E = ICE->getSubExpr();
    } else if (const auto *CSE = dyn_cast<CStyleCastExpr>(E)) {
      E = CSE->getSubExpr();
    } else {
      break;
    }
  }
  return E;
}

static bool sameResourceExpr(const Expr *A, const Expr *B) {
  A = strip(A);
  B = strip(B);
  if (!A || !B)
    return false;

  if (const auto *DREA = dyn_cast<DeclRefExpr>(A)) {
    if (const auto *DREB = dyn_cast<DeclRefExpr>(B))
      return DREA->getDecl() == DREB->getDecl();
  }

  if (const auto *MEA = dyn_cast<MemberExpr>(A)) {
    if (const auto *MEB = dyn_cast<MemberExpr>(B)) {
      return MEA->getMemberDecl() == MEB->getMemberDecl() &&
             sameResourceExpr(MEA->getBase(), MEB->getBase());
    }
  }

  return false;
}

static bool isCallToRole(const CallExpr *CE, StringRef Role) {
  if (!CE)
    return false;

  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD)
    return false;

  return knighter::isRole(Role, FD->getName());
}

static bool findOwnershipTransferInStmt(const Stmt *S, const Expr *Op1,
                                        const Expr *Op2, const Expr *&Resource,
                                        const CallExpr *&Transfer) {
  if (!S)
    return false;

  // Check assignment whose RHS is the ownership-transfer call.
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *RHS = strip(BO->getRHS());
      if (const auto *CE = dyn_cast<CallExpr>(RHS)) {
        if (isCallToRole(CE, "ownership_transfer")) {
          const Expr *LHS = strip(BO->getLHS());
          if (sameResourceExpr(LHS, Op1)) {
            Resource = Op2;
            Transfer = CE;
            return true;
          } else if (sameResourceExpr(LHS, Op2)) {
            Resource = Op1;
            Transfer = CE;
            return true;
          }
        }
      }
    }
  }

  // Fallback: direct ownership-transfer call with exactly one condition
  // operand as an argument.
  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (isCallToRole(CE, "ownership_transfer")) {
      const Expr *Found = nullptr;
      unsigned MatchCount = 0;
      for (unsigned I = 0, E = CE->getNumArgs(); I != E; ++I) {
        const Expr *Arg = strip(CE->getArg(I));
        if (sameResourceExpr(Arg, Op1)) {
          Found = Op1;
          ++MatchCount;
        } else if (sameResourceExpr(Arg, Op2)) {
          Found = Op2;
          ++MatchCount;
        }
      }
      if (MatchCount == 1) {
        Resource = Found;
        Transfer = CE;
        return true;
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (findOwnershipTransferInStmt(Child, Op1, Op2, Resource, Transfer))
      return true;
  }
  return false;
}

static bool hasDeallocatorCall(const Stmt *S, const Expr *Resource) {
  if (!S)
    return false;

  if (const auto *CE = dyn_cast<CallExpr>(S)) {
    if (isCallToRole(CE, "deallocator")) {
      for (unsigned I = 0, E = CE->getNumArgs(); I != E; ++I) {
        if (sameResourceExpr(strip(CE->getArg(I)), Resource))
          return true;
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    if (hasDeallocatorCall(Child, Resource))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Resource Leak", "Memory Management")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &Ctx) const;
};

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &Ctx) const {
  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, Ctx);
  if (!IS || IS->getCond() != Condition)
    return;

  const Expr *Cond = strip(IS->getCond());
  const auto *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO || BO->getOpcode() != BO_LAnd)
    return;

  const Expr *Op1 = strip(BO->getLHS());
  const Expr *Op2 = strip(BO->getRHS());
  if (!Op1 || !Op2)
    return;

  const Expr *Resource = nullptr;
  const CallExpr *Transfer = nullptr;
  if (!findOwnershipTransferInStmt(IS->getThen(), Op1, Op2, Resource, Transfer))
    return;
  if (!Resource || !Transfer)
    return;

  const Stmt *Else = IS->getElse();
  if (Else && hasDeallocatorCall(Else, Resource))
    return;

  ExplodedNode *N = Ctx.generateNonFatalErrorNode();
  if (!N)
    return;

  auto BR = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential resource leak: missing deallocation when ownership transfer is skipped",
      N);
  BR->addRange(Condition->getSourceRange());
  Ctx.emitReport(std::move(BR));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing deallocation when ownership transfer is skipped",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "resource_allocator": {"names": ["sqlite3SrcListDup", "sqlite3SelectNew", "sqlite3SrcListAppendFromTerm"], "description": "functions that create or rebuild a resource pointer"},
  "ownership_transfer": {"names": ["sqlite3SrcListAppendList"], "description": "function that consumes a resource into a destination owner"},
  "deallocator": {"names": ["sqlite3SrcListDelete"], "description": "function that frees the resource"}
}
*/
