#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/OperationKinds.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;

namespace {

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() : BT(new BugType(this, "Integer Overflow", "Memory Error")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

} // end anonymous namespace

// Helper: check if type is signed integer with bit width < 64
static bool isSignedIntegerLessThan64(const VarDecl *VD, ASTContext &AC) {
  QualType QT = VD->getType();
  if (!QT->isSignedIntegerType())
    return false;
  unsigned Bits = AC.getTypeSize(QT);
  return Bits < 64;
}

// Helper: does stmt contain a multiplication operator?
static bool containsMul(const Stmt *S) {
  if (!S)
    return false;
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Mul)
      return true;
  }
  for (const Stmt *Child : S->children()) {
    if (containsMul(Child))
      return true;
  }
  return false;
}

// Helper: does stmt contain a compound assignment (+=) on VD whose RHS contains a multiplication?
static bool containsAccumulation(const Stmt *S, const VarDecl *VD) {
  if (!S)
    return false;
  if (const CompoundAssignOperator *CAO = dyn_cast<CompoundAssignOperator>(S)) {
    if (CAO->getOpcode() == BO_AddAssign) {
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(CAO->getLHS()->IgnoreParenImpCasts())) {
        if (DRE->getDecl() == VD) {
          if (containsMul(CAO->getRHS()))
            return true;
        }
      }
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsAccumulation(Child, VD))
      return true;
  }
  return false;
}

// Helper: does stmt contain a reference to VD?
static bool containsVarRef(const Stmt *S, const VarDecl *VD) {
  if (!S)
    return false;
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S)) {
    return DRE->getDecl() == VD;
  }
  for (const Stmt *Child : S->children()) {
    if (containsVarRef(Child, VD))
      return true;
  }
  return false;
}

// Helper: does stmt contain an IfStmt whose condition references VD?
static bool containsIfCheckingVar(const Stmt *S, const VarDecl *VD) {
  if (!S)
    return false;
  if (const IfStmt *IS = dyn_cast<IfStmt>(S)) {
    if (containsVarRef(IS->getCond(), VD))
      return true;
  }
  for (const Stmt *Child : S->children()) {
    if (containsIfCheckingVar(Child, VD))
      return true;
  }
  return false;
}

namespace {
class LoopChecker : public RecursiveASTVisitor<LoopChecker> {
  const VarDecl *VD;

public:
  bool FoundUnchecked = false;
  explicit LoopChecker(const VarDecl *VD) : VD(VD) {}

  bool VisitWhileStmt(WhileStmt *S) { return checkLoop(S, S->getBody()); }
  bool VisitForStmt(ForStmt *S) { return checkLoop(S, S->getBody()); }
  bool VisitDoStmt(DoStmt *S) { return checkLoop(S, S->getBody()); }

private:
  bool checkLoop(const Stmt *Loop, const Stmt *Body) {
    if (FoundUnchecked)
      return true;
    if (!Body)
      return true;
    if (!containsAccumulation(Body, VD))
      return true;
    if (containsIfCheckingVar(Body, VD))
      return true;
    FoundUnchecked = true;
    return false; // stop traversal
  }
};
} // namespace

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  if (!knighter::declIsRole(FD, "parser_input"))
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  ASTContext &AC = FD->getASTContext();
  llvm::SmallPtrSet<const VarDecl *, 8> Reported;

  // Collect all init calls in the function body.
  class InitVisitor : public RecursiveASTVisitor<InitVisitor> {
  public:
    ASTContext &AC;
    SmallVectorImpl<const CallExpr *> &InitCalls;
    InitVisitor(ASTContext &AC, SmallVectorImpl<const CallExpr *> &Calls)
        : AC(AC), InitCalls(Calls) {}
    bool VisitCallExpr(CallExpr *CE) {
      if (knighter::callExprIsRole(CE, "init", AC)) {
        InitCalls.push_back(CE);
      }
      return true;
    }
  };

  SmallVector<const CallExpr *, 8> InitCalls;
  InitVisitor IV(AC, InitCalls);
  IV.TraverseStmt(const_cast<Stmt *>(Body));

  for (const CallExpr *CE : InitCalls) {
    if (CE->getNumArgs() < 3)
      continue;
    const Expr *SizeArg = CE->getArg(2)->IgnoreParenImpCasts();
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(SizeArg);
    if (!DRE)
      continue;
    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      continue;
    if (!isSignedIntegerLessThan64(VD, AC))
      continue;
    if (Reported.count(VD))
      continue;

    LoopChecker Checker(VD);
    Checker.TraverseStmt(const_cast<Stmt *>(Body));
    if (Checker.FoundUnchecked) {
      auto Report = std::make_unique<BasicBugReport>(
          *BT,
          "Potential integer overflow in untrusted size accumulation before "
          "memory initialization",
          PathDiagnosticLocation::createBegin(CE, BR.getSourceManager(),
                                               nullptr));
      BR.emitReport(std::move(Report));
      Reported.insert(VD);
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in untrusted size accumulation before memory "
      "initialization",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["kvvfsDecode"], "description": "parses an untrusted encoded input stream"},
  "init": {"names": ["memset"], "description": "initializes/writes a number of bytes into a memory buffer"}
}
*/
