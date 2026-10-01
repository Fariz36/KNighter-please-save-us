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
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class OutputParamFinder : public RecursiveASTVisitor<OutputParamFinder> {
  const ParmVarDecl *Target;
  bool Found = false;

public:
  explicit OutputParamFinder(const ParmVarDecl *P) : Target(P) {}

  bool found() const { return Found; }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (Found)
      return true;
    if (BO->getOpcode() != BO_Assign)
      return true;

    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const UnaryOperator *UO = dyn_cast<UnaryOperator>(LHS);
    if (!UO || UO->getOpcode() != UO_Deref)
      return true;

    const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub);
    if (!DRE)
      return true;

    if (DRE->getDecl() == Target)
      Found = true;

    return true;
  }
};

static bool isPointerToPointer(QualType QT) {
  if (!QT->isPointerType())
    return false;
  return QT->getPointeeType()->isPointerType();
}

class SAGenTestChecker
    : public Checker<check::ASTCodeBody, check::PreStmt<ReturnStmt>> {
  mutable std::unique_ptr<BugType> BT;
  mutable llvm::DenseMap<const FunctionDecl *,
                         llvm::SmallVector<const ParmVarDecl *, 4>>
      OutputParams;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Success return with NULL output parameter",
                       "API Misuse")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;

private:
  void reportBug(const ReturnStmt *RS, const ParmVarDecl *P,
                 CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->getBody())
    return;

  llvm::SmallVector<const ParmVarDecl *, 4> Params;
  for (const ParmVarDecl *P : FD->parameters()) {
    if (!isPointerToPointer(P->getType()))
      continue;

    OutputParamFinder Finder(P);
    Finder.TraverseStmt(FD->getBody());
    if (Finder.found())
      Params.push_back(P);
  }

  if (!Params.empty())
    OutputParams[FD] = std::move(Params);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const LocationContext *LCtx = C.getLocationContext();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(LCtx->getDecl());
  if (!FD)
    return;

  auto It = OutputParams.find(FD);
  if (It == OutputParams.end() || It->second.empty())
    return;

  const Expr *RetE = RS->getRetValue();
  if (!RetE)
    return;

  SVal RetVal = State->getSVal(RetE, LCtx);
  bool Success = false;

  if (auto CI = RetVal.getAs<nonloc::ConcreteInt>()) {
    if (CI->getValue().isZero())
      Success = true;
  } else if (SymbolRef Sym = RetVal.getAsSymbol()) {
    const llvm::APSInt *Val =
        State->getConstraintManager().getSymVal(State, Sym);
    if (Val && Val->isZero())
      Success = true;
  }

  if (!Success)
    return;

  for (const ParmVarDecl *P : It->second) {
    SVal PVal = State->getSVal(State->getRegion(P, LCtx));
    auto PValLoc = PVal.getAs<Loc>();
    if (!PValLoc)
      continue;

    SVal Loaded = State->getSVal(*PValLoc);
    if (State->isNull(Loaded).isConstrainedTrue()) {
      reportBug(RS, P, C);
    }
  }
}

void SAGenTestChecker::reportBug(const ReturnStmt *RS, const ParmVarDecl *P,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Success return with NULL output parameter", N);
  Report->addRange(RS->getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects functions that return success while leaving an output parameter NULL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
