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
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class VarRefFinder : public RecursiveASTVisitor<VarRefFinder> {
  const VarDecl *VD;
  bool Found = false;

public:
  explicit VarRefFinder(const VarDecl *VD) : VD(VD) {}

  bool visitDeclRefExpr(DeclRefExpr *DRE) {
    if (DRE->getDecl() == VD) {
      Found = true;
      return false;
    }
    return true;
  }

  bool found() const { return Found; }
};

bool referencesVar(const Expr *E, const VarDecl *VD) {
  if (!E || !VD)
    return false;
  VarRefFinder Finder(VD);
  Finder.TraverseStmt(const_cast<Expr *>(E));
  return Finder.found();
}

class ReturnFinder : public RecursiveASTVisitor<ReturnFinder> {
  bool Found = false;

public:
  bool visitReturnStmt(ReturnStmt *RS) {
    Found = true;
    return false;
  }

  bool found() const { return Found; }
};

bool hasReturnStmt(const Stmt *S) {
  if (!S)
    return false;
  ReturnFinder Finder;
  Finder.TraverseStmt(const_cast<Stmt *>(S));
  return Finder.found();
}

class IncFinder : public RecursiveASTVisitor<IncFinder> {
  const VarDecl *Found = nullptr;

public:
  bool visitUnaryOperator(UnaryOperator *UO) {
    if (UO->isIncrementDecrementOp()) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub)) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          Found = VD;
          return false;
        }
      }
    }
    return true;
  }

  const VarDecl *getFound() const { return Found; }
};

const VarDecl *findCounterVar(const ForStmt *FS) {
  if (!FS)
    return nullptr;

  // Search the loop body for a variable that is incremented/decremented.
  if (const Stmt *Body = FS->getBody()) {
    IncFinder Finder;
    Finder.TraverseStmt(const_cast<Stmt *>(Body));
    if (const VarDecl *VD = Finder.getFound())
      return VD;
  }

  // Fallback: take the last variable declared in the loop init.
  if (const Stmt *Init = FS->getInit()) {
    if (const DeclStmt *DS = dyn_cast<DeclStmt>(Init)) {
      const VarDecl *Last = nullptr;
      for (const Decl *D : DS->decls()) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(D))
          Last = VD;
      }
      return Last;
    }
  }
  return nullptr;
}

bool hasPostLoopCheck(const CompoundStmt *CS, const ForStmt *FS,
                      const VarDecl *CntVar) {
  bool AfterLoop = false;
  for (const Stmt *S : CS->body()) {
    if (S == FS) {
      AfterLoop = true;
      continue;
    }
    if (!AfterLoop)
      continue;
    if (const IfStmt *If = dyn_cast<IfStmt>(S)) {
      const Expr *Cond = If->getCond();
      if (referencesVar(Cond, CntVar)) {
        if (hasReturnStmt(If->getThen()))
          return true;
      }
    }
  }
  return false;
}

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing Base64 validation", "Base64 decoder")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  if (FD->getNameAsString() != "DecodeBase64")
    return;

  const CompoundStmt *CS = dyn_cast<CompoundStmt>(FD->getBody());
  if (!CS)
    return;

  const ForStmt *MainLoop = nullptr;
  for (const Stmt *S : CS->body()) {
    if (const ForStmt *FS = dyn_cast<ForStmt>(S)) {
      MainLoop = FS;
      break;
    }
  }
  if (!MainLoop)
    return;

  const VarDecl *CntVar = findCounterVar(MainLoop);
  if (!CntVar)
    return;

  if (hasPostLoopCheck(CS, MainLoop, CntVar))
    return;

  if (!BT)
    return;

  PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(
      MainLoop, BR.getSourceManager(), nullptr);
  auto Report = std::make_unique<BasicBugReport>(
      *BT,
      "DecodeBase64 does not reject truncated input: missing check for "
      "leftover characters after the decoding loop.",
      Loc);
  BR.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing post-loop validation in DecodeBase64",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
