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
#include "clang/AST/DeclBase.h"
#include "clang/AST/OperationKinds.h"
#include "clang/Basic/SourceManager.h"
#include "knighter/roles.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// ---------------------------------------------------------------------------
// Helper: source-order comparison
// ---------------------------------------------------------------------------
static bool isBefore(const Stmt *S1, const Stmt *S2, SourceManager &SM) {
  if (!S1 || !S2)
    return false;
  SourceLocation L1 = S1->getBeginLoc();
  SourceLocation L2 = S2->getBeginLoc();
  if (L1.isInvalid() || L2.isInvalid())
    return false;
  return SM.isBeforeInTranslationUnit(L1, L2);
}

// ---------------------------------------------------------------------------
// Helper: find a DeclRefExpr that refers to a specific VarDecl
// ---------------------------------------------------------------------------
class VarRefToDeclFinder : public RecursiveASTVisitor<VarRefToDeclFinder> {
  const VarDecl *V;
  bool Found = false;

public:
  explicit VarRefToDeclFinder(const VarDecl *V) : V(V) {}
  bool found() const { return Found; }
  bool VisitDeclRefExpr(DeclRefExpr *DRE) {
    if (DRE->getDecl() == V) {
      Found = true;
      return false;
    }
    return true;
  }
};

static bool exprReferencesVar(const Expr *E, const VarDecl *V) {
  if (!E || !V)
    return false;
  VarRefToDeclFinder F(V);
  F.TraverseStmt(const_cast<Expr *>(E));
  return F.found();
}

// ---------------------------------------------------------------------------
// Helper: find a VarDecl by role inside an Expr or Stmt
// ---------------------------------------------------------------------------
class VarRefFinder : public RecursiveASTVisitor<VarRefFinder> {
  StringRef Role;
  const VarDecl *Found = nullptr;

public:
  explicit VarRefFinder(StringRef Role) : Role(Role) {}
  const VarDecl *found() const { return Found; }
  bool VisitDeclRefExpr(DeclRefExpr *DRE) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (knighter::declIsRole(VD, Role)) {
        Found = VD;
        return false;
      }
    }
    return true;
  }
};

static const VarDecl *findVarInExpr(const Expr *E, StringRef Role) {
  if (!E)
    return nullptr;
  VarRefFinder F(Role);
  F.TraverseStmt(const_cast<Expr *>(E));
  return F.found();
}

static const VarDecl *findVarInStmt(const Stmt *S, StringRef Role) {
  if (!S)
    return nullptr;
  VarRefFinder F(Role);
  F.TraverseStmt(const_cast<Stmt *>(S));
  return F.found();
}

// ---------------------------------------------------------------------------
// Helper: detect increments of a specific VarDecl
// ---------------------------------------------------------------------------
class IncrementFinder : public RecursiveASTVisitor<IncrementFinder> {
  const VarDecl *V;
  bool Found = false;

public:
  explicit IncrementFinder(const VarDecl *V) : V(V) {}
  bool found() const { return Found; }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (UO->isIncrementDecrementOp()) {
      const Expr *E = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
        if (DRE->getDecl() == V) {
          Found = true;
          return false;
        }
      }
    }
    return true;
  }

  bool VisitCompoundAssignOperator(CompoundAssignOperator *CAO) {
    if (CAO->getOpcode() == BO_AddAssign) {
      const Expr *LHS = CAO->getLHS()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (DRE->getDecl() == V) {
          Found = true;
          return false;
        }
      }
    }
    return true;
  }
};

static bool loopIncrementsVar(Stmt *Loop, const VarDecl *V) {
  if (ForStmt *FS = dyn_cast<ForStmt>(Loop)) {
    if (FS->getInc()) {
      IncrementFinder F(V);
      F.TraverseStmt(FS->getInc());
      if (F.found())
        return true;
    }
  }

  const Stmt *Body = nullptr;
  if (const ForStmt *FS = dyn_cast<ForStmt>(Loop))
    Body = FS->getBody();
  else if (const WhileStmt *WS = dyn_cast<WhileStmt>(Loop))
    Body = WS->getBody();
  else if (const DoStmt *DS = dyn_cast<DoStmt>(Loop))
    Body = DS->getBody();

  if (Body) {
    IncrementFinder F(V);
    F.TraverseStmt(const_cast<Stmt *>(Body));
    if (F.found())
      return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helper: locate the loop that increments the continuation counter
// ---------------------------------------------------------------------------
class LoopFinder : public RecursiveASTVisitor<LoopFinder> {
  const VarDecl *V;
  const Stmt *Found = nullptr;

public:
  explicit LoopFinder(const VarDecl *V) : V(V) {}
  const Stmt *found() const { return Found; }

  bool VisitForStmt(ForStmt *FS) {
    if (loopIncrementsVar(FS, V)) {
      Found = FS;
      return false;
    }
    return true;
  }
  bool VisitWhileStmt(WhileStmt *WS) {
    if (loopIncrementsVar(WS, V)) {
      Found = WS;
      return false;
    }
    return true;
  }
  bool VisitDoStmt(DoStmt *DS) {
    if (loopIncrementsVar(DS, V)) {
      Found = DS;
      return false;
    }
    return true;
  }
};

// ---------------------------------------------------------------------------
// Helper: does a statement contain a return / break / continue?
// ---------------------------------------------------------------------------
class AbruptStmtFinder : public RecursiveASTVisitor<AbruptStmtFinder> {
  bool Found = false;

public:
  bool found() const { return Found; }
  bool VisitReturnStmt(ReturnStmt *RS) {
    Found = true;
    return false;
  }
  bool VisitBreakStmt(BreakStmt *BS) {
    Found = true;
    return false;
  }
  bool VisitContinueStmt(ContinueStmt *CS) {
    Found = true;
    return false;
  }
};

static bool hasAbruptBranch(const Stmt *S) {
  if (!S)
    return false;
  AbruptStmtFinder F;
  F.TraverseStmt(const_cast<Stmt *>(S));
  return F.found();
}

// ---------------------------------------------------------------------------
// Helper: does a statement contain another statement?
// ---------------------------------------------------------------------------
class StmtContainsFinder : public RecursiveASTVisitor<StmtContainsFinder> {
  const Stmt *Target;
  bool Found = false;

public:
  explicit StmtContainsFinder(const Stmt *Target) : Target(Target) {}
  bool found() const { return Found; }
  bool VisitStmt(Stmt *S) {
    if (S == Target) {
      Found = true;
      return false;
    }
    return true;
  }
};

static bool stmtContains(const Stmt *Parent, const Stmt *Child) {
  if (!Parent || !Child)
    return false;
  if (Parent == Child)
    return true;
  StmtContainsFinder F(Child);
  F.TraverseStmt(const_cast<Stmt *>(Parent));
  return F.found();
}

// A branch is an abrupt guard only if it exits without containing the
// dangerous statement (loop or shift) inside the same branch.
static bool hasAbruptBranchExcluding(const Stmt *Branch, const Stmt *Exclude) {
  if (!Branch)
    return false;
  if (stmtContains(Branch, Exclude))
    return false;
  return hasAbruptBranch(Branch);
}

// ---------------------------------------------------------------------------
// Helper: does an expression contain an integer literal?
// ---------------------------------------------------------------------------
class IntLiteralFinder : public RecursiveASTVisitor<IntLiteralFinder> {
  bool Found = false;

public:
  bool found() const { return Found; }
  bool VisitIntegerLiteral(IntegerLiteral *IL) {
    Found = true;
    return false;
  }
};

static bool exprHasIntegerLiteral(const Expr *E) {
  if (!E)
    return false;
  IntLiteralFinder F;
  F.TraverseStmt(const_cast<Expr *>(E));
  return F.found();
}

// ---------------------------------------------------------------------------
// Helper: find a pre-shift guard around the loop or the shift
// ---------------------------------------------------------------------------
class GuardFinder : public RecursiveASTVisitor<GuardFinder> {
  const Stmt *Loop;
  const BinaryOperator *BO;
  const VarDecl *InputVar;
  const VarDecl *CountVar;
  SourceManager &SM;
  bool Found = false;

public:
  GuardFinder(const Stmt *Loop, const BinaryOperator *BO,
              const VarDecl *IV, const VarDecl *CV, SourceManager &SM)
      : Loop(Loop), BO(BO), InputVar(IV), CountVar(CV), SM(SM) {}

  bool found() const { return Found; }

  bool VisitIfStmt(IfStmt *IS) {
    if (Found)
      return false;

    const Expr *Cond = IS->getCond();
    if (!Cond)
      return true;

    // A guard before the loop that validates the input byte.
    if (Loop && isBefore(IS, Loop, SM)) {
      if (exprReferencesVar(Cond, InputVar)) {
        if (hasAbruptBranchExcluding(IS->getThen(), Loop) ||
            hasAbruptBranchExcluding(IS->getElse(), Loop)) {
          Found = true;
          return false;
        }
      }
    }

    // A guard before the shift that validates the continuation count.
    if (BO && isBefore(IS, BO, SM)) {
      if (exprReferencesVar(Cond, CountVar) && exprHasIntegerLiteral(Cond)) {
        if (hasAbruptBranchExcluding(IS->getThen(), BO) ||
            hasAbruptBranchExcluding(IS->getElse(), BO)) {
          Found = true;
          return false;
        }
      }
    }

    return true;
  }
};

// ---------------------------------------------------------------------------
// The checker
// ---------------------------------------------------------------------------
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Shift Overflow", "Integer Shift")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

private:
  void analyzeShift(const BinaryOperator *BO, AnalysisManager &Mgr,
                    BugReporter &BR, const FunctionDecl *FD) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  if (!D)
    return;

  const NamedDecl *ND = dyn_cast<NamedDecl>(D);
  if (!ND || !knighter::declIsRole(ND, "decoder_function"))
    return;

  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  class ShiftVisitor : public RecursiveASTVisitor<ShiftVisitor> {
    const SAGenTestChecker &Checker;
    AnalysisManager &Mgr;
    BugReporter &BR;
    const FunctionDecl *FD;

  public:
    ShiftVisitor(const SAGenTestChecker &C, AnalysisManager &M,
                 BugReporter &B, const FunctionDecl *F)
        : Checker(C), Mgr(M), BR(B), FD(F) {}

    bool VisitBinaryOperator(BinaryOperator *BO) {
      if (BO->getOpcode() == BO_Shl)
        Checker.analyzeShift(BO, Mgr, BR, FD);
      return true;
    }
  };

  ShiftVisitor V(*this, Mgr, BR, FD);
  V.TraverseStmt(Body);
}

void SAGenTestChecker::analyzeShift(const BinaryOperator *BO,
                                    AnalysisManager &Mgr, BugReporter &BR,
                                    const FunctionDecl *FD) const {
  // The RHS of the shift must be a multiplication.
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  const BinaryOperator *Mul = dyn_cast<BinaryOperator>(RHS);
  if (!Mul || Mul->getOpcode() != BO_Mul)
    return;

  // Find the continuation-count variable in the multiplication.
  const VarDecl *CountVar = nullptr;
  const Expr *Other = nullptr;
  for (const Expr *Operand : {Mul->getLHS(), Mul->getRHS()}) {
    const Expr *E = Operand->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (knighter::declIsRole(VD, "continuation_count")) {
          CountVar = VD;
          Other = (Operand == Mul->getLHS()) ? Mul->getRHS() : Mul->getLHS();
          break;
        }
      }
    }
  }
  if (!CountVar)
    return;

  // The other operand should be an integer literal (the multiplier).
  const Expr *MulOperand = Other->IgnoreParenImpCasts();
  if (!isa<IntegerLiteral>(MulOperand))
    return;

  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  // Find the loop that increments the continuation count.
  LoopFinder LF(CountVar);
  LF.TraverseStmt(Body);
  const Stmt *Loop = LF.found();
  if (!Loop)
    return;

  // Find the input-byte variable in the loop condition or body.
  const VarDecl *InputVar = nullptr;
  const Expr *Cond = nullptr;
  if (const ForStmt *FS = dyn_cast<ForStmt>(Loop))
    Cond = FS->getCond();
  else if (const WhileStmt *WS = dyn_cast<WhileStmt>(Loop))
    Cond = WS->getCond();
  else if (const DoStmt *DS = dyn_cast<DoStmt>(Loop))
    Cond = DS->getCond();

  if (Cond)
    InputVar = findVarInExpr(Cond, "input_byte");

  if (!InputVar) {
    const Stmt *LoopBody = nullptr;
    if (const ForStmt *FS = dyn_cast<ForStmt>(Loop))
      LoopBody = FS->getBody();
    else if (const WhileStmt *WS = dyn_cast<WhileStmt>(Loop))
      LoopBody = WS->getBody();
    else if (const DoStmt *DS = dyn_cast<DoStmt>(Loop))
      LoopBody = DS->getBody();

    if (LoopBody)
      InputVar = findVarInStmt(LoopBody, "input_byte");
  }

  if (!InputVar)
    return;

  // Check for a pre-loop input guard or a pre-shift count guard.
  SourceManager &SM = Mgr.getSourceManager();
  GuardFinder GF(Loop, BO, InputVar, CountVar, SM);
  GF.TraverseStmt(Body);

  if (!GF.found()) {
    auto Report = std::make_unique<BasicBugReport>(
        *BT,
        "Shift amount may exceed bit width due to unchecked continuation count",
        PathDiagnosticLocation(BO->getOperatorLoc(), Mgr.getSourceManager()));
    Report->addRange(BO->getSourceRange());
    BR.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked continuation count leading to oversized shift",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "decoder_function": {"names": ["utf8_decode"], "description": "Function that decodes a UTF-8 sequence"},
  "input_byte": {"names": ["c"], "description": "Variable holding the first byte of the UTF-8 sequence"},
  "continuation_count": {"names": ["count"], "description": "Variable counting the number of continuation bytes"}
}
*/
