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
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Check whether an expression refers to a declaration that plays the given role.
static bool exprRefersToRole(const Expr *E, llvm::StringRef Role) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    const ValueDecl *VD = DRE->getDecl();
    return VD && knighter::declIsRole(VD, Role);
  }

  if (const MemberExpr *ME = dyn_cast<MemberExpr>(E)) {
    const ValueDecl *VD = ME->getMemberDecl();
    return VD && knighter::declIsRole(VD, Role);
  }

  return false;
}

// Check whether an expression is the integer literal 1.
static bool isIntegerLiteralOne(const Expr *E) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E))
    return IL->getValue() == 1;

  return false;
}

class OverflowPageCountVisitor
    : public RecursiveASTVisitor<OverflowPageCountVisitor> {
  ASTContext &Ctx;
  BugReporter &BR;
  const Decl *D;
  const CheckerBase *Checker;

public:
  OverflowPageCountVisitor(ASTContext &Ctx, BugReporter &BR, const Decl *D,
                           const CheckerBase *Checker)
      : Ctx(Ctx), BR(BR), D(D), Checker(Checker) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (!BO || BO->getOpcode() != BO_Div)
      return true;

    // Denominator must be the overflow chunk size.
    const Expr *Denom = BO->getRHS()->IgnoreParenImpCasts();
    if (!exprRefersToRole(Denom, "overflow_chunk_size"))
      return true;

    // Numerator must be: (payload_length - local_payload_length +
    //                     overflow_chunk_size - 1)
    const Expr *Num = BO->getLHS()->IgnoreParenImpCasts();

    const BinaryOperator *Sub1 = dyn_cast<BinaryOperator>(Num);
    if (!Sub1 || Sub1->getOpcode() != BO_Sub)
      return true;
    if (!isIntegerLiteralOne(Sub1->getRHS()))
      return true;

    const BinaryOperator *Add =
        dyn_cast<BinaryOperator>(Sub1->getLHS()->IgnoreParenImpCasts());
    if (!Add || Add->getOpcode() != BO_Add)
      return true;

    const BinaryOperator *Sub2 =
        dyn_cast<BinaryOperator>(Add->getLHS()->IgnoreParenImpCasts());
    if (!Sub2 || Sub2->getOpcode() != BO_Sub)
      return true;

    if (!exprRefersToRole(Sub2->getLHS(), "payload_length"))
      return true;
    if (!exprRefersToRole(Sub2->getRHS(), "local_payload_length"))
      return true;
    if (!exprRefersToRole(Add->getRHS(), "overflow_chunk_size"))
      return true;

    // The arithmetic is performed in a too-narrow type if it is <= 32 bits.
    QualType ArithTy = Num->getType();
    if (Ctx.getTypeSize(ArithTy) <= 32) {
      BR.EmitBasicReport(
          D, Checker,
          "Integer overflow in overflow page count",
          "Integer overflow",
          "Overflow page count computed in 32-bit arithmetic; promote to "
          "64-bit before subtraction/addition/division.",
          PathDiagnosticLocation(BO, Ctx.getSourceManager(), nullptr));
    }

    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
    if (!FD)
      return;

    const Stmt *Body = FD->getBody();
    if (!Body)
      return;

    ASTContext &Ctx = Mgr.getASTContext();
    OverflowPageCountVisitor Visitor(Ctx, BR, D, this);
    Visitor.TraverseStmt(const_cast<Stmt *>(Body));
  }
};

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects 32-bit integer overflow in overflow page count computations",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "payload_length": {"names": ["nPayload"], "description": "length of the payload being read/written in a btree cell"},
  "local_payload_length": {"names": ["nLocal"], "description": "amount of payload stored locally on the current btree page"},
  "overflow_chunk_size": {"names": ["ovflSize"], "description": "number of usable bytes per overflow page"},
  "overflow_page_cache": {"names": ["aOverflow"], "description": "cache of overflow page numbers"},
  "reallocator": {"names": ["sqlite3Realloc"], "description": "memory reallocation function"},
  "allocated_size_query": {"names": ["sqlite3MallocSize"], "description": "function returning the allocated size of a memory block"},
  "zero_initializer": {"names": ["memset"], "description": "memory zeroing function"},
  "cache_index": {"names": ["iIdx"], "description": "index into the overflow page cache"},
  "too_narrow_arithmetic_type": {"names": ["int", "u32"], "description": "integer type narrower than 64 bits that can overflow in size computations"}
}
*/
