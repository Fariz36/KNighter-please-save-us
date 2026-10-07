#include <memory>

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

#include "clang/AST/AST.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/APSInt.h"
#include "knighter/roles.h"

// PathDiagnosticLocation (used below) is provided transitively by BugReporter.h.

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper: check if expression references any variable in Vars.
static bool exprReferencesVars(const Expr *E,
                               const llvm::SmallPtrSetImpl<const VarDecl *> &Vars) {
  if (!E) return false;
  class Finder : public RecursiveASTVisitor<Finder> {
    const llvm::SmallPtrSetImpl<const VarDecl *> &Vars;
  public:
    bool Found = false;
    Finder(const llvm::SmallPtrSetImpl<const VarDecl *> &V) : Vars(V) {}
    bool VisitDeclRefExpr(DeclRefExpr *DRE) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (Vars.contains(VD)) {
          Found = true;
          return false;
        }
      }
      return true;
    }
  };
  Finder F(Vars);
  F.TraverseStmt(const_cast<Expr*>(E));
  return F.Found;
}

// Helper: collect local VarDecls and assignments.
class FuncBodyVarCollector : public RecursiveASTVisitor<FuncBodyVarCollector> {
public:
  llvm::SmallVector<const VarDecl*, 16> VarDecls;
  llvm::SmallVector<const BinaryOperator*, 16> Assigns;
  llvm::SmallVector<const CompoundAssignOperator*, 16> CompoundAssigns;

  bool VisitVarDecl(VarDecl *VD) {
    if (VD->isLocalVarDecl()) VarDecls.push_back(VD);
    return true;
  }
  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_Assign) Assigns.push_back(BO);
    return true;
  }
  bool VisitCompoundAssignOperator(CompoundAssignOperator *CAO) {
    CompoundAssigns.push_back(CAO);
    return true;
  }
};

// Helper: find memory-writer calls and their size argument.
class MemoryWriterCallFinder : public RecursiveASTVisitor<MemoryWriterCallFinder> {
public:
  llvm::SmallVector<const DeclRefExpr*, 4> SizeArgDREs;
  bool VisitCallExpr(CallExpr *CE) {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD) return true;
    if (knighter::declIsRole(FD, "bounded_copy")) {
      if (CE->getNumArgs() > 2) {
        const Expr *SizeArg = CE->getArg(2)->IgnoreParenImpCasts();
        if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(SizeArg)) {
          SizeArgDREs.push_back(DRE);
        }
      }
    }
    return true;
  }
};

// Helper: check if expression reads from untrusted input.
static bool exprReadsInput(const Expr *E,
                           const llvm::SmallPtrSetImpl<const VarDecl*> &InputVars,
                           const VarDecl *SizeVar) {
  if (!E) return false;
  class Finder : public RecursiveASTVisitor<Finder> {
    const llvm::SmallPtrSetImpl<const VarDecl*> &InputVars;
    const VarDecl *SizeVar;
  public:
    bool Found = false;
    Finder(const llvm::SmallPtrSetImpl<const VarDecl*> &IV, const VarDecl *SV)
        : InputVars(IV), SizeVar(SV) {}
    bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
      const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base)) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          if (InputVars.contains(VD) && VD != SizeVar) {
            Found = true;
            return false;
          }
        }
      }
      return true;
    }
    bool VisitUnaryOperator(UnaryOperator *UO) {
      if (UO->getOpcode() == UO_Deref) {
        const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
        if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub)) {
          if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
            if (InputVars.contains(VD) && VD != SizeVar) {
              Found = true;
              return false;
            }
          }
        }
      }
      return true;
    }
    bool VisitDeclRefExpr(DeclRefExpr *DRE) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (InputVars.contains(VD) && VD != SizeVar) {
          Found = true;
          return false;
        }
      }
      return true;
    }
  };
  Finder F(InputVars, SizeVar);
  F.TraverseStmt(const_cast<Expr*>(E));
  return F.Found;
}

// Helper: find a local variable multiplied in an expression.
class MulVarFinder : public RecursiveASTVisitor<MulVarFinder> {
public:
  const VarDecl *SizeVar;
  const VarDecl *MultiplierVar = nullptr;
  MulVarFinder(const VarDecl *SV) : SizeVar(SV) {}
  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_Mul && !MultiplierVar) {
      for (const Expr *Op : {BO->getLHS(), BO->getRHS()}) {
        const Expr *E = Op->IgnoreParenImpCasts();
        if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
          if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
            if (VD != SizeVar && VD->isLocalVarDecl()) {
              MultiplierVar = VD;
              return false;
            }
          }
        }
      }
    }
    return true;
  }
};

// Helper: evaluate an expression to an integer.
static bool evaluateInt(llvm::APSInt &Result, const Expr *E, ASTContext &Ctx) {
  if (!E) return false;
  Expr::EvalResult ER;
  if (E->EvaluateAsInt(ER, Ctx)) {
    Result = ER.Val.getInt();
    return true;
  }
  return false;
}

// Helper: check for exponential multiplier growth.
class MultiplierGrowthFinder : public RecursiveASTVisitor<MultiplierGrowthFinder> {
public:
  ASTContext &Ctx;
  const VarDecl *MultiplierVar;
  bool Found = false;
  MultiplierGrowthFinder(ASTContext &C, const VarDecl *MV) : Ctx(C), MultiplierVar(MV) {}
  bool VisitCompoundAssignOperator(CompoundAssignOperator *CAO) {
    if (Found) return true;
    const Expr *LHS = CAO->getLHS()->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
      if (DRE->getDecl() == MultiplierVar && CAO->getOpcode() == BO_MulAssign) {
        llvm::APSInt Val;
        if (evaluateInt(Val, CAO->getRHS(), Ctx) && Val > 1) {
          Found = true;
          return false;
        }
      }
    }
    return true;
  }
  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (Found) return true;
    if (BO->getOpcode() != BO_Assign) return true;
    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
      if (DRE->getDecl() == MultiplierVar) {
        const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
        if (const BinaryOperator *Mul = dyn_cast<BinaryOperator>(RHS)) {
          if (Mul->getOpcode() == BO_Mul) {
            const Expr *Op1 = Mul->getLHS()->IgnoreParenImpCasts();
            const Expr *Op2 = Mul->getRHS()->IgnoreParenImpCasts();
            bool op1IsVar = false, op2IsVar = false;
            if (const DeclRefExpr *DRE1 = dyn_cast<DeclRefExpr>(Op1)) {
              if (DRE1->getDecl() == MultiplierVar) op1IsVar = true;
            }
            if (const DeclRefExpr *DRE2 = dyn_cast<DeclRefExpr>(Op2)) {
              if (DRE2->getDecl() == MultiplierVar) op2IsVar = true;
            }
            if (op1IsVar || op2IsVar) {
              const Expr *ConstExpr = op1IsVar ? Op2 : Op1;
              llvm::APSInt Val;
              if (evaluateInt(Val, ConstExpr, Ctx) && Val > 1) {
                Found = true;
                return false;
              }
            }
          }
        }
      }
    }
    return true;
  }
};

// Helper: find updates to SizeVar and the enclosing loop.
class SizeUpdateFinder : public RecursiveASTVisitor<SizeUpdateFinder> {
public:
  ASTContext &Ctx;
  const VarDecl *SizeVar;
  const llvm::SmallPtrSetImpl<const VarDecl*> &InputVars;
  llvm::SmallVector<const Stmt*, 8> LoopStack;
  const Stmt *InnermostLoop = nullptr;
  const VarDecl *MultiplierVar = nullptr;
  bool FoundUpdate = false;

  SizeUpdateFinder(ASTContext &C, const VarDecl *SV,
                   const llvm::SmallPtrSetImpl<const VarDecl*> &IV)
      : Ctx(C), SizeVar(SV), InputVars(IV) {}

  bool TraverseWhileStmt(WhileStmt *S) {
    LoopStack.push_back(S);
    bool ret = RecursiveASTVisitor<SizeUpdateFinder>::TraverseWhileStmt(S);
    LoopStack.pop_back();
    return ret;
  }
  bool TraverseForStmt(ForStmt *S) {
    LoopStack.push_back(S);
    bool ret = RecursiveASTVisitor<SizeUpdateFinder>::TraverseForStmt(S);
    LoopStack.pop_back();
    return ret;
  }
  bool TraverseDoStmt(DoStmt *S) {
    LoopStack.push_back(S);
    bool ret = RecursiveASTVisitor<SizeUpdateFinder>::TraverseDoStmt(S);
    LoopStack.pop_back();
    return ret;
  }

  bool VisitCompoundAssignOperator(CompoundAssignOperator *CAO) {
    if (FoundUpdate) return true;
    const Expr *LHS = CAO->getLHS()->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
      if (DRE->getDecl() == SizeVar) {
        if (CAO->getOpcode() == BO_AddAssign) {
          analyzeUpdate(CAO->getRHS());
        }
      }
    }
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (FoundUpdate) return true;
    if (BO->getOpcode() != BO_Assign) return true;
    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
      if (DRE->getDecl() == SizeVar) {
        analyzeUpdate(BO->getRHS());
      }
    }
    return true;
  }

private:
  void analyzeUpdate(const Expr *RHS) {
    if (!RHS) return;
    if (!exprReadsInput(RHS, InputVars, SizeVar)) return;
    MulVarFinder MVF(SizeVar);
    MVF.TraverseStmt(const_cast<Expr*>(RHS));
    if (!MVF.MultiplierVar) return;
    MultiplierVar = MVF.MultiplierVar;
    InnermostLoop = LoopStack.empty() ? nullptr : LoopStack.back();
    FoundUpdate = true;
  }
};

// Helper: check if expression contains a given variable.
static bool exprContainsVar(const Expr *E, const VarDecl *VD) {
  if (!E) return false;
  class Finder : public RecursiveASTVisitor<Finder> {
    const VarDecl *VD;
  public:
    bool Found = false;
    Finder(const VarDecl *V) : VD(V) {}
    bool VisitDeclRefExpr(DeclRefExpr *DRE) {
      if (DRE->getDecl() == VD) {
        Found = true;
        return false;
      }
      return true;
    }
  };
  Finder F(VD);
  F.TraverseStmt(const_cast<Expr*>(E));
  return F.Found;
}

// Helper: check if a statement contains a return/break/continue.
static bool containsAbort(const Stmt *S) {
  if (!S) return false;
  if (isa<ReturnStmt>(S) || isa<BreakStmt>(S) || isa<ContinueStmt>(S)) return true;
  for (const Stmt *Child : S->children()) {
    if (containsAbort(Child)) return true;
  }
  return false;
}

// Helper: check if a condition is a bound check involving SizeVar.
static bool isBoundCheck(const Expr *Cond, const VarDecl *SizeVar) {
  if (!Cond) return false;
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts());
  if (!BO) return false;
  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GT && Op != BO_GE && Op != BO_LT && Op != BO_LE && Op != BO_EQ && Op != BO_NE)
    return false;
  return exprContainsVar(BO->getLHS(), SizeVar) || exprContainsVar(BO->getRHS(), SizeVar);
}

// Helper: check for an early bound check in a loop body.
static bool hasEarlyBoundCheck(const Stmt *S, const VarDecl *SizeVar) {
  if (!S) return false;
  if (const IfStmt *IS = dyn_cast<IfStmt>(S)) {
    if (isBoundCheck(IS->getCond(), SizeVar)) {
      if (containsAbort(IS->getThen())) return true;
    }
  }
  for (const Stmt *Child : S->children()) {
    if (!Child) continue;
    if (isa<WhileStmt>(Child) || isa<ForStmt>(Child) || isa<DoStmt>(Child)) continue;
    if (hasEarlyBoundCheck(Child, SizeVar)) return true;
  }
  return false;
}

// Helper: check if a VarDecl is a small signed integer.
static bool isSmallSignedInteger(const VarDecl *VD, ASTContext &Ctx) {
  QualType QT = VD->getType();
  if (!QT->isIntegerType()) return false;
  if (!QT->isSignedIntegerType()) return false;
  unsigned Width = Ctx.getIntWidth(QT);
  return Width < 64;
}

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Untrusted size overflow", "integer overflow")) {}
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD) return;
  if (!knighter::declIsRole(FD, "parser_input")) return;
  if (!FD->hasBody()) return;
  const Stmt *Body = FD->getBody();
  if (!Body) return;

  ASTContext &Ctx = Mgr.getASTContext();

  // Step 2: Identify untrusted input variables
  llvm::SmallPtrSet<const VarDecl*, 8> InputVars;
  for (const ParmVarDecl *P : FD->parameters()) {
    if (P->getType()->isPointerType())
      InputVars.insert(P);
  }

  FuncBodyVarCollector Collector;
  Collector.TraverseStmt(const_cast<Stmt*>(Body));

  bool Changed = true;
  while (Changed) {
    Changed = false;
    for (const VarDecl *VD : Collector.VarDecls) {
      if (InputVars.contains(VD)) continue;
      if (VD->hasInit() && exprReferencesVars(VD->getInit(), InputVars)) {
        InputVars.insert(VD);
        Changed = true;
      }
    }
    for (const BinaryOperator *BO : Collector.Assigns) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          if (!InputVars.contains(VD) && exprReferencesVars(RHS, InputVars)) {
            InputVars.insert(VD);
            Changed = true;
          }
        }
      }
    }
    for (const CompoundAssignOperator *CAO : Collector.CompoundAssigns) {
      const Expr *LHS = CAO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = CAO->getRHS();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          if (!InputVars.contains(VD) && exprReferencesVars(RHS, InputVars)) {
            InputVars.insert(VD);
            Changed = true;
          }
        }
      }
    }
  }

  // Step 3: Locate memory-writer calls
  MemoryWriterCallFinder MWF;
  MWF.TraverseStmt(const_cast<Stmt*>(Body));

  for (const DeclRefExpr *SizeDRE : MWF.SizeArgDREs) {
    const VarDecl *SizeVar = dyn_cast<VarDecl>(SizeDRE->getDecl());
    if (!SizeVar) continue;

    // Step 4 & 7: Find update and innermost loop
    SizeUpdateFinder SUF(Ctx, SizeVar, InputVars);
    SUF.TraverseStmt(const_cast<Stmt*>(Body));
    if (!SUF.FoundUpdate) continue;
    if (!SUF.MultiplierVar) continue;

    // Step 5: Verify exponential multiplier growth
    MultiplierGrowthFinder MGF(Ctx, SUF.MultiplierVar);
    MGF.TraverseStmt(const_cast<Stmt*>(Body));
    if (!MGF.Found) continue;

    // Step 6: Check integer types
    if (!isSmallSignedInteger(SizeVar, Ctx)) continue;
    if (!isSmallSignedInteger(SUF.MultiplierVar, Ctx)) continue;

    // Step 7: Check for early bound validation
    if (SUF.InnermostLoop) {
      const Stmt *LoopBody = nullptr;
      if (const WhileStmt *WS = dyn_cast<WhileStmt>(SUF.InnermostLoop)) {
        LoopBody = WS->getBody();
      } else if (const ForStmt *FS = dyn_cast<ForStmt>(SUF.InnermostLoop)) {
        LoopBody = FS->getBody();
      } else if (const DoStmt *DS = dyn_cast<DoStmt>(SUF.InnermostLoop)) {
        LoopBody = DS->getBody();
      }
      if (LoopBody && hasEarlyBoundCheck(LoopBody, SizeVar)) {
        continue; // early bound check exists
      }
    }

    // Step 8: Report
    BR.EmitBasicReport(D, this, "Untrusted size overflow", "integer overflow",
                       "Untrusted size accumulated without early bound check before memory write.",
                       PathDiagnosticLocation::create(D, BR.getSourceManager()));
    break; // Report once per function
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects untrusted size accumulation without early bound check before memory write",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["kvvfsDecode"], "description": "function that decodes or parses externally supplied bytes; its pointer parameters are untrusted input sources"},
  "bounded_copy": {"names": ["memset"], "description": "function that writes a specified number of bytes into a destination buffer; the size argument must be bounded"}
}
*/
