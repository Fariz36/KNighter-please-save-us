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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/SmallVector.h"
#include "knighter/roles.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper: check if an expression refers to a specific VarDecl.
static bool isRefToVar(const Expr *E, const VarDecl *VD) {
  if (!E || !VD)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    return DRE->getDecl() == VD;
  }
  return false;
}

// Visitor to check whether a statement contains a reference to a VarDecl.
class ContainsVarRefVisitor
    : public RecursiveASTVisitor<ContainsVarRefVisitor> {
  const VarDecl *VD;
  bool Found = false;

public:
  explicit ContainsVarRefVisitor(const VarDecl *VD) : VD(VD) {}

  bool VisitDeclRefExpr(DeclRefExpr *DRE) {
    if (DRE->getDecl() == VD) {
      Found = true;
      return false;
    }
    return true;
  }

  bool found() const { return Found; }
};

// Finds the first arithmetic BinaryOperator that uses a given VarDecl.
class ExpansionFinder : public RecursiveASTVisitor<ExpansionFinder> {
  const VarDecl *Candidate;
  const BinaryOperator *Found = nullptr;

public:
  explicit ExpansionFinder(const VarDecl *Candidate) : Candidate(Candidate) {}

  // Do not look for arithmetic inside if conditions; only inside the branches.
  bool TraverseIfStmt(IfStmt *IS) {
    if (IS->getThen() && !TraverseStmt(IS->getThen()))
      return false;
    if (IS->getElse() && !TraverseStmt(IS->getElse()))
      return false;
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (Found)
      return false;

    if (!BO->isAssignmentOp()) {
      BinaryOperator::Opcode Op = BO->getOpcode();
      if (Op == BO_Add || Op == BO_Sub || Op == BO_Mul || Op == BO_Div) {
        ContainsVarRefVisitor V(Candidate);
        V.TraverseStmt(BO);
        if (V.found()) {
          Found = BO;
          return false;
        }
      }
    }
    return true;
  }

  const BinaryOperator *found() const { return Found; }
};

// Collects integer local variables that may carry untrusted size values.
class CandidateCollector : public RecursiveASTVisitor<CandidateCollector> {
  ASTContext &Ctx;
  llvm::SmallVectorImpl<const VarDecl *> &Candidates;

public:
  CandidateCollector(ASTContext &Ctx,
                     llvm::SmallVectorImpl<const VarDecl *> &Candidates)
      : Ctx(Ctx), Candidates(Candidates) {}

  bool VisitVarDecl(VarDecl *VD) {
    if (!VD->getType()->isIntegerType())
      return true;
    if (!VD->hasInit())
      return true;

    const Expr *Init = VD->getInit()->IgnoreParenImpCasts();
    if (!Init)
      return true;

    if (isa<MemberExpr>(Init)) {
      Candidates.push_back(VD);
      return true;
    }

    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Init)) {
      if (isa<ParmVarDecl>(DRE->getDecl())) {
        Candidates.push_back(VD);
        return true;
      }
    }

    if (const CallExpr *CE = dyn_cast<CallExpr>(Init)) {
      if (knighter::callExprIsRole(CE, "untrusted_size", Ctx)) {
        Candidates.push_back(VD);
        return true;
      }
    }

    return true;
  }
};

// Collects all IfStmt nodes in a function body.
class IfCollector : public RecursiveASTVisitor<IfCollector> {
  llvm::SmallVectorImpl<const IfStmt *> &Ifs;

public:
  explicit IfCollector(llvm::SmallVectorImpl<const IfStmt *> &Ifs)
      : Ifs(Ifs) {}

  bool VisitIfStmt(IfStmt *IS) {
    Ifs.push_back(IS);
    return true;
  }
};

// Finds a comparison BinaryOperator in an if condition that involves the
// candidate on either side.
class GuardComparisonFinder
    : public RecursiveASTVisitor<GuardComparisonFinder> {
  const VarDecl *Candidate;
  const BinaryOperator *Found = nullptr;

public:
  explicit GuardComparisonFinder(const VarDecl *Candidate)
      : Candidate(Candidate) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (Found)
      return false;

    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op != BO_LT && Op != BO_LE && Op != BO_GT && Op != BO_GE)
      return true;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

    bool L = isRefToVar(LHS, Candidate);
    bool R = isRefToVar(RHS, Candidate);
    if (!L && !R)
      return true;

    const Expr *Other = L ? RHS : LHS;
    if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(Other)) {
      if (IL->getValue().isZero())
        return true;
    }

    if (!Other->getType()->isIntegerType())
      return true;

    Found = BO;
    return false;
  }

  const BinaryOperator *found() const { return Found; }
};

// Checks whether a branch contains a terminating statement or aborting call.
class TerminatorFinder : public RecursiveASTVisitor<TerminatorFinder> {
  ASTContext &Ctx;
  bool Found = false;

public:
  explicit TerminatorFinder(ASTContext &Ctx) : Ctx(Ctx) {}

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

  bool VisitCallExpr(CallExpr *CE) {
    if (knighter::callExprIsRole(CE, "aborting_assert", Ctx)) {
      Found = true;
      return false;
    }
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      if (FD->getName() == "abort") {
        Found = true;
        return false;
      }
    }
    return true;
  }

  bool found() const { return Found; }
};

static bool branchTerminates(const Stmt *S, ASTContext &Ctx) {
  if (!S)
    return false;
  TerminatorFinder V(Ctx);
  V.TraverseStmt(const_cast<Stmt *>(S));
  return V.found();
}

static bool ifGuardsUpperBound(const IfStmt *If, const VarDecl *Candidate,
                               const BinaryOperator *Expansion,
                               ASTContext &Ctx, SourceManager &SM) {
  if (!If || !Candidate || !Expansion)
    return false;

  SourceLocation IfLoc = If->getBeginLoc();
  SourceLocation ExpLoc = Expansion->getBeginLoc();
  if (!IfLoc.isValid() || !ExpLoc.isValid() ||
      !SM.isBeforeInTranslationUnit(IfLoc, ExpLoc))
    return false;

  const Expr *Cond = If->getCond();
  if (!Cond)
    return false;

  GuardComparisonFinder Finder(Candidate);
  Finder.TraverseStmt(const_cast<Expr *>(Cond));
  const BinaryOperator *Cmp = Finder.found();
  if (!Cmp)
    return false;

  bool CandOnLeft = isRefToVar(Cmp->getLHS()->IgnoreParenImpCasts(), Candidate);
  BinaryOperator::Opcode Op = Cmp->getOpcode();

  bool TrueIsTooLarge = false;
  if (CandOnLeft) {
    if (Op == BO_GT || Op == BO_GE)
      TrueIsTooLarge = true;
    else
      TrueIsTooLarge = false;
  } else {
    if (Op == BO_LT || Op == BO_LE)
      TrueIsTooLarge = true;
    else
      TrueIsTooLarge = false;
  }

  const Stmt *Branch = TrueIsTooLarge ? If->getThen() : If->getElse();
  return branchTerminates(Branch, Ctx);
}

} // end anonymous namespace

namespace {
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked size expansion", "Integer overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  if (!knighter::declIsRole(FD, "length_of"))
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  ASTContext &Ctx = Mgr.getASTContext();
  SourceManager &SM = Ctx.getSourceManager();

  llvm::SmallVector<const VarDecl *, 8> Candidates;

  for (const ParmVarDecl *P : FD->parameters()) {
    if (P->getType()->isIntegerType())
      Candidates.push_back(P);
  }

  CandidateCollector Collector(Ctx, Candidates);
  Collector.TraverseStmt(const_cast<Stmt *>(Body));

  llvm::SmallVector<const IfStmt *, 8> Ifs;
  IfCollector IfColl(Ifs);
  IfColl.TraverseStmt(const_cast<Stmt *>(Body));

  for (const VarDecl *Candidate : Candidates) {
    ExpansionFinder ExpFinder(Candidate);
    ExpFinder.TraverseStmt(const_cast<Stmt *>(Body));
    const BinaryOperator *Expansion = ExpFinder.found();
    if (!Expansion)
      continue;

    bool Guarded = false;
    for (const IfStmt *If : Ifs) {
      if (ifGuardsUpperBound(If, Candidate, Expansion, Ctx, SM)) {
        Guarded = true;
        break;
      }
    }

    if (!Guarded) {
      auto Report = std::make_unique<BasicBugReport>(
          *BT,
          "Potential integer overflow in size expansion: untrusted size is "
          "not upper-bound checked before arithmetic.",
          PathDiagnosticLocation::createBegin(Expansion, SM, nullptr));
      BR.emitReport(std::move(Report));
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked size-expansion arithmetic on untrusted input length",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "length_of": {"names": ["encoder_base64_size"], "description": "computes an expanded/encoded output length from an input size; callers trust the returned length"},
  "untrusted_size": {"names": [], "description": "a function or macro that returns an untrusted size; in this project the input is a struct field, so it is recognized structurally rather than by name"},
  "aborting_assert": {"names": ["aborting_assert"], "description": "macro that stops execution when its condition is false, so a branch containing it terminates"}
}
*/
