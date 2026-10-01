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
#include "clang/Basic/SourceManager.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing TK_ILLEGAL check", "SQLite")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  bool isSqlite3Dequote(const CallEvent &Call, CheckerContext &C) const;
  const FunctionDecl *getEnclosingFunction(CheckerContext &C) const;
  bool hasTKIllegalGuardBefore(const Stmt *Body, SourceLocation CallLoc,
                               CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isSqlite3Dequote(const CallEvent &Call,
                                        CheckerContext &C) const {
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  return ExprHasName(OriginExpr, "sqlite3Dequote", C);
}

const FunctionDecl *
SAGenTestChecker::getEnclosingFunction(CheckerContext &C) const {
  const LocationContext *LC = C.getLocationContext();
  if (!LC)
    return nullptr;
  const Decl *D = LC->getDecl();
  if (!D)
    return nullptr;
  return dyn_cast<FunctionDecl>(D);
}

bool SAGenTestChecker::hasTKIllegalGuardBefore(const Stmt *Body,
                                               SourceLocation CallLoc,
                                               CheckerContext &C) const {
  if (!Body || !CallLoc.isValid())
    return false;

  const SourceManager &SM = C.getSourceManager();

  class GuardFinder : public RecursiveASTVisitor<GuardFinder> {
    CheckerContext &C;
    SourceLocation CallLoc;
    const SourceManager &SM;
    bool Found = false;

  public:
    GuardFinder(CheckerContext &C, SourceLocation CallLoc)
        : C(C), CallLoc(CallLoc), SM(C.getSourceManager()) {}

    bool VisitIfStmt(IfStmt *IS) {
      if (Found)
        return false;
      if (!IS)
        return true;

      // The guard condition must mention TK_ILLEGAL.
      if (!ExprHasName(IS->getCond(), "TK_ILLEGAL", C))
        return true;

      // Either branch must contain a return statement (early exit).
      bool HasReturn = false;
      if (IS->getThen()) {
        HasReturn =
            (findSpecificTypeInChildren<ReturnStmt>(IS->getThen()) != nullptr);
      }
      if (!HasReturn && IS->getElse()) {
        HasReturn =
            (findSpecificTypeInChildren<ReturnStmt>(IS->getElse()) != nullptr);
      }
      if (!HasReturn)
        return true;

      // The guard must appear before the sqlite3Dequote call.
      SourceLocation IfLoc = IS->getIfLoc();
      if (IfLoc.isValid() && SM.isBeforeInTranslationUnit(IfLoc, CallLoc)) {
        Found = true;
        return false;
      }
      return true;
    }

    bool found() const { return Found; }
  };

  GuardFinder Finder(C, CallLoc);
  Finder.TraverseStmt(const_cast<Stmt *>(Body));
  return Finder.found();
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isSqlite3Dequote(Call, C))
    return;

  const FunctionDecl *FD = getEnclosingFunction(C);
  if (!FD || FD->getNameAsString() != "quotedCompare")
    return;

  const Expr *CallExpr = Call.getOriginExpr();
  if (!CallExpr)
    return;

  SourceLocation CallLoc = CallExpr->getBeginLoc();
  if (hasTKIllegalGuardBefore(FD->getBody(), CallLoc, C))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing TK_ILLEGAL check before sqlite3Dequote", N);
  Report->addRange(CallExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing TK_ILLEGAL check before sqlite3Dequote in quotedCompare",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
