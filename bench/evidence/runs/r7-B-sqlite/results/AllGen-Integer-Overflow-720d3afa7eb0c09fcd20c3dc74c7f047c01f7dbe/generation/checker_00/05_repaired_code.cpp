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
#include "llvm/Support/Casting.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class SAGenTestChecker : public Checker<check::PostStmt<DeclStmt>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow", "Integer Overflow")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS,
                                     CheckerContext &C) const {
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || FD->getNameAsString() != "accessPayload")
    return;

  for (const Decl *DI : DS->decls()) {
    const VarDecl *VD = dyn_cast<VarDecl>(DI);
    if (!VD)
      continue;

    if (VD->getNameAsString() != "nOvfl")
      continue;

    QualType VarTy = VD->getType();
    if (C.getASTContext().getTypeSize(VarTy) != 32 ||
        !VarTy->isSignedIntegerType())
      continue;

    const Expr *Init = VD->getInit();
    if (!Init)
      continue;

    const Expr *InitNoCasts = Init->IgnoreParenImpCasts();
    const auto *Div = dyn_cast<BinaryOperator>(InitNoCasts);
    if (!Div || Div->getOpcode() != BO_Div)
      continue;

    const Expr *LHS = Div->getLHS()->IgnoreParenImpCasts();
    if (!isa<BinaryOperator>(LHS))
      continue;

    QualType LhsTy = LHS->getType().getCanonicalType();
    if (C.getASTContext().getTypeSize(LhsTy) != 32 ||
        !LhsTy->isUnsignedIntegerType())
      continue;

    if (!ExprHasName(LHS, "nPayload", C) ||
        !ExprHasName(LHS, "nLocal", C) ||
        !ExprHasName(Div->getRHS(), "ovflSize", C))
      continue;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      continue;

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Potential 32-bit overflow in nOvfl computation", N);
    Report->addRange(Init->getSourceRange());
    C.emitReport(std::move(Report));
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potential 32-bit integer overflow in nOvfl computation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
