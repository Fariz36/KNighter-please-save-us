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
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class VarRefFinder : public RecursiveASTVisitor<VarRefFinder> {
  const VarDecl *Target;
  bool Found = false;

public:
  explicit VarRefFinder(const VarDecl *VD) : Target(VD) {}

  bool VisitDeclRefExpr(DeclRefExpr *DRE) {
    if (DRE->getDecl() == Target) {
      Found = true;
      return false;
    }
    return true;
  }

  bool found() const { return Found; }
};

bool exprReferencesVar(const Expr *E, const VarDecl *VD) {
  if (!E || !VD)
    return false;
  VarRefFinder Finder(VD);
  Finder.TraverseStmt(const_cast<Expr *>(E));
  return Finder.found();
}

bool isRelationalOp(BinaryOperator::Opcode Op) {
  return Op == BO_LT || Op == BO_GT || Op == BO_LE || Op == BO_GE;
}

bool isBoundsCheck(const IfStmt *IS, const VarDecl *LengthAcc,
                   const VarDecl *OutCap) {
  if (!IS || !LengthAcc || !OutCap)
    return false;
  const Expr *Cond = IS->getCond();
  if (!Cond)
    return false;
  Cond = Cond->IgnoreParenCasts();
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO || !isRelationalOp(BO->getOpcode()))
    return false;
  return exprReferencesVar(Cond, LengthAcc) &&
         exprReferencesVar(Cond, OutCap);
}

bool isAccumulatorUpdate(const Stmt *S, const VarDecl *LengthAcc,
                         const VarDecl *PlaceMult) {
  if (const CompoundAssignOperator *CAO =
          dyn_cast<CompoundAssignOperator>(S)) {
    if (CAO->getOpcode() == BO_AddAssign) {
      return exprReferencesVar(CAO->getLHS(), LengthAcc) &&
             exprReferencesVar(CAO->getRHS(), PlaceMult);
    }
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      if (!exprReferencesVar(BO->getLHS(), LengthAcc))
        return false;
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      if (const BinaryOperator *Add = dyn_cast<BinaryOperator>(RHS)) {
        if (Add->getOpcode() == BO_Add) {
          return exprReferencesVar(Add, LengthAcc) &&
                 exprReferencesVar(Add, PlaceMult);
        }
      }
    }
  }
  return false;
}

bool isMultiplierUpdate(const Stmt *S, const VarDecl *PlaceMult) {
  if (const CompoundAssignOperator *CAO =
          dyn_cast<CompoundAssignOperator>(S)) {
    if (CAO->getOpcode() == BO_MulAssign) {
      return exprReferencesVar(CAO->getLHS(), PlaceMult);
    }
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      if (!exprReferencesVar(BO->getLHS(), PlaceMult))
        return false;
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();
      if (const BinaryOperator *Mul = dyn_cast<BinaryOperator>(RHS)) {
        if (Mul->getOpcode() == BO_Mul) {
          return exprReferencesVar(Mul, PlaceMult);
        }
      }
    }
  }
  return false;
}

bool isBufferWriterCall(const CallExpr *CE) {
  if (!CE)
    return false;
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    return knighter::isRole("buffer_writer", FD->getNameAsString());
  }
  if (const Expr *Callee = CE->getCallee()) {
    if (const DeclRefExpr *DRE =
            dyn_cast<DeclRefExpr>(Callee->IgnoreParenImpCasts())) {
      if (const NamedDecl *ND = dyn_cast<NamedDecl>(DRE->getDecl())) {
        return knighter::isRole("buffer_writer", ND->getNameAsString());
      }
    }
  }
  return false;
}

bool callReferencesVars(const CallExpr *CE, const VarDecl *V1,
                        const VarDecl *V2) {
  if (!CE || !V1 || !V2)
    return false;
  bool Ref1 = false;
  bool Ref2 = false;
  for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
    const Expr *Arg = CE->getArg(i);
    if (exprReferencesVar(Arg, V1))
      Ref1 = true;
    if (exprReferencesVar(Arg, V2))
      Ref2 = true;
  }
  return Ref1 && Ref2;
}

class RoleVarCollector : public RecursiveASTVisitor<RoleVarCollector> {
public:
  const VarDecl *LengthAcc = nullptr;
  const VarDecl *PlaceMult = nullptr;
  const VarDecl *OutputOffset = nullptr;
  const VarDecl *OutputCapacity = nullptr;
  llvm::SmallVector<const VarDecl *, 4> UntrustedInputs;

  bool VisitVarDecl(VarDecl *VD) {
    if (knighter::declIsRole(VD, "untrusted_input"))
      UntrustedInputs.push_back(VD);
    if (knighter::declIsRole(VD, "length_accumulator"))
      LengthAcc = VD;
    if (knighter::declIsRole(VD, "place_value_multiplier"))
      PlaceMult = VD;
    if (knighter::declIsRole(VD, "output_offset"))
      OutputOffset = VD;
    if (knighter::declIsRole(VD, "output_capacity"))
      OutputCapacity = VD;
    return true;
  }
};

class FunctionInfoCollector
    : public RecursiveASTVisitor<FunctionInfoCollector> {
public:
  llvm::ArrayRef<const VarDecl *> UntrustedInputs;
  llvm::SmallVector<const DeclRefExpr *, 8> UntrustedReads;
  llvm::SmallVector<const CallExpr *, 8> BufferWriters;

  explicit FunctionInfoCollector(llvm::ArrayRef<const VarDecl *> UI)
      : UntrustedInputs(UI) {}

  bool VisitDeclRefExpr(DeclRefExpr *DRE) {
    for (const VarDecl *VD : UntrustedInputs) {
      if (DRE->getDecl() == VD) {
        UntrustedReads.push_back(DRE);
        break;
      }
    }
    return true;
  }

  bool VisitCallExpr(CallExpr *CE) {
    if (isBufferWriterCall(CE))
      BufferWriters.push_back(CE);
    return true;
  }
};

class AccMultFinder : public RecursiveASTVisitor<AccMultFinder> {
public:
  const VarDecl *LengthAcc;
  const VarDecl *PlaceMult;
  const VarDecl *OutputCapacity;
  llvm::SmallVector<const Stmt *, 8> AccUpdates;
  llvm::SmallVector<const Stmt *, 8> MultUpdates;
  llvm::SmallVector<const IfStmt *, 8> BoundsChecks;

  AccMultFinder(const VarDecl *LA, const VarDecl *PM, const VarDecl *OC)
      : LengthAcc(LA), PlaceMult(PM), OutputCapacity(OC) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (isAccumulatorUpdate(BO, LengthAcc, PlaceMult))
      AccUpdates.push_back(BO);
    if (isMultiplierUpdate(BO, PlaceMult))
      MultUpdates.push_back(BO);
    return true;
  }

  bool VisitIfStmt(IfStmt *IS) {
    if (isBoundsCheck(IS, LengthAcc, OutputCapacity))
      BoundsChecks.push_back(IS);
    return true;
  }
};

class LoopVisitor : public RecursiveASTVisitor<LoopVisitor> {
public:
  const VarDecl *LengthAcc;
  const VarDecl *PlaceMult;
  const VarDecl *OutputOffset;
  const VarDecl *OutputCapacity;
  llvm::ArrayRef<const VarDecl *> UntrustedInputs;
  llvm::ArrayRef<const DeclRefExpr *> UntrustedReads;
  llvm::ArrayRef<const CallExpr *> BufferWriters;
  const SourceManager &SM;
  BugReporter &BR;
  BugType &BT;
  llvm::SmallPtrSet<const Stmt *, 8> &Reported;

  LoopVisitor(const VarDecl *LA, const VarDecl *PM, const VarDecl *OO,
              const VarDecl *OC, llvm::ArrayRef<const VarDecl *> UI,
              llvm::ArrayRef<const DeclRefExpr *> UR,
              llvm::ArrayRef<const CallExpr *> BW, const SourceManager &SM,
              BugReporter &BR, BugType &BT,
              llvm::SmallPtrSet<const Stmt *, 8> &Reported)
      : LengthAcc(LA), PlaceMult(PM), OutputOffset(OO), OutputCapacity(OC),
        UntrustedInputs(UI), UntrustedReads(UR), BufferWriters(BW), SM(SM),
        BR(BR), BT(BT), Reported(Reported) {}

  bool VisitWhileStmt(WhileStmt *WS) {
    analyzeLoop(WS->getBody());
    return true;
  }

  bool VisitForStmt(ForStmt *FS) {
    analyzeLoop(FS->getBody());
    return true;
  }

  bool VisitDoStmt(DoStmt *DS) {
    analyzeLoop(DS->getBody());
    return true;
  }

private:
  void analyzeLoop(const Stmt *Body);
};

void LoopVisitor::analyzeLoop(const Stmt *Body) {
  if (!Body)
    return;

  AccMultFinder Finder(LengthAcc, PlaceMult, OutputCapacity);
  Finder.TraverseStmt(const_cast<Stmt *>(Body));

  for (const Stmt *Acc : Finder.AccUpdates) {
    if (Reported.count(Acc))
      continue;

    SourceLocation AccLoc = Acc->getBeginLoc();
    if (!AccLoc.isValid())
      continue;

    for (const Stmt *Mult : Finder.MultUpdates) {
      SourceLocation MultLoc = Mult->getBeginLoc();
      if (!MultLoc.isValid())
        continue;
      if (!SM.isBeforeInTranslationUnit(AccLoc, MultLoc))
        continue;

      bool HasIntervening = false;
      for (const IfStmt *BC : Finder.BoundsChecks) {
        SourceLocation BCLoc = BC->getBeginLoc();
        if (!BCLoc.isValid())
          continue;
        if (SM.isBeforeInTranslationUnit(AccLoc, BCLoc) &&
            SM.isBeforeInTranslationUnit(BCLoc, MultLoc)) {
          HasIntervening = true;
          break;
        }
      }
      if (HasIntervening)
        continue;

      bool HasUntrustedBefore = false;
      for (const DeclRefExpr *DRE : UntrustedReads) {
        SourceLocation ReadLoc = DRE->getBeginLoc();
        if (ReadLoc.isValid() &&
            SM.isBeforeInTranslationUnit(ReadLoc, AccLoc)) {
          HasUntrustedBefore = true;
          break;
        }
      }
      if (!HasUntrustedBefore)
        continue;

      bool HasWriter = false;
      for (const CallExpr *CE : BufferWriters) {
        if (!callReferencesVars(CE, LengthAcc, OutputOffset))
          continue;
        SourceLocation CallLoc = CE->getBeginLoc();
        if (CallLoc.isValid() &&
            SM.isBeforeInTranslationUnit(MultLoc, CallLoc)) {
          HasWriter = true;
          break;
        }
      }
      if (!HasWriter)
        continue;

      Reported.insert(Acc);
      PathDiagnosticLocation Pos =
          PathDiagnosticLocation::createBegin(Acc, SM, nullptr);
      auto Report = std::make_unique<BasicBugReport>(
          BT, "integer overflow in length accumulator before bounds check",
          Pos);
      Report->addRange(Acc->getSourceRange());
      BR.emitReport(std::move(Report));
      break;
    }
  }
}

} // end anonymous namespace

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow in Length Accumulator",
                       "Integer Overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  RoleVarCollector Collector;
  Collector.TraverseDecl(const_cast<FunctionDecl *>(FD));

  const VarDecl *LengthAcc = Collector.LengthAcc;
  const VarDecl *PlaceMult = Collector.PlaceMult;
  const VarDecl *OutputOffset = Collector.OutputOffset;
  const VarDecl *OutputCapacity = Collector.OutputCapacity;

  if (!LengthAcc || !PlaceMult || !OutputOffset || !OutputCapacity)
    return;
  if (Collector.UntrustedInputs.empty())
    return;

  ASTContext &Ctx = FD->getASTContext();
  std::string NType = LengthAcc->getType().getAsString(Ctx.getPrintingPolicy());
  std::string MType = PlaceMult->getType().getAsString(Ctx.getPrintingPolicy());

  if (knighter::isRole("widened_safe_type_in_fix", NType) ||
      knighter::isRole("widened_safe_type_in_fix", MType))
    return;

  if (!knighter::isRole("fixed_width_signed_arithmetic_type", NType) ||
      !knighter::isRole("fixed_width_signed_arithmetic_type", MType))
    return;

  FunctionInfoCollector Info(Collector.UntrustedInputs);
  Info.TraverseStmt(const_cast<Stmt *>(Body));

  llvm::SmallPtrSet<const Stmt *, 8> Reported;
  LoopVisitor Visitor(LengthAcc, PlaceMult, OutputOffset, OutputCapacity,
                      Collector.UntrustedInputs, Info.UntrustedReads,
                      Info.BufferWriters, BR.getSourceManager(), BR, *BT,
                      Reported);
  Visitor.TraverseStmt(const_cast<Stmt *>(Body));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in length accumulators before bounds checks",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "untrusted_input": {"names": ["aIn", "a"], "description": "pointer or array containing untrusted encoded input"},
  "length_accumulator": {"names": ["n"], "description": "variable accumulating a decoded length from untrusted input"},
  "place_value_multiplier": {"names": ["mult"], "description": "base multiplier used when accumulating a length"},
  "output_offset": {"names": ["j"], "description": "current write offset into the output buffer"},
  "output_capacity": {"names": ["nOut"], "description": "maximum size of the output buffer"},
  "buffer_writer": {"names": ["memset"], "description": "function that writes to a buffer using a size argument"},
  "fixed_width_signed_arithmetic_type": {"names": ["int"], "description": "fixed-width signed integer type that can overflow"},
  "widened_safe_type_in_fix": {"names": ["sqlite3_int64"], "description": "widened integer type that avoids overflow in this context"}
}
*/
