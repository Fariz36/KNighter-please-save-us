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
#include "knighter/roles.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Visitor to collect all assignments to a given VarDecl.
class AssignmentCollector : public RecursiveASTVisitor<AssignmentCollector> {
public:
  const VarDecl *SizeVar;
  llvm::SmallVector<const Stmt *, 4> Assignments;

  explicit AssignmentCollector(const VarDecl *SV) : SizeVar(SV) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (!BO->isAssignmentOp())
      return true;
    const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS);
    if (!DRE)
      return true;
    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (VD == SizeVar)
      Assignments.push_back(BO);
    return true;
  }
};

// Visitor to detect multiplication inside an expression.
class MulFinder : public RecursiveASTVisitor<MulFinder> {
public:
  bool Found = false;
  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_Mul || BO->getOpcode() == BO_MulAssign) {
      Found = true;
      return false;
    }
    return true;
  }
};

// Visitor to check if an expression contains a comparison with a specific VarDecl.
class SizeComparisonFinder : public RecursiveASTVisitor<SizeComparisonFinder> {
public:
  const VarDecl *SizeVar;
  bool Found = false;

  explicit SizeComparisonFinder(const VarDecl *SV) : SizeVar(SV) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->isComparisonOp()) {
      if (isDeclRefToVar(BO->getLHS(), SizeVar) ||
          isDeclRefToVar(BO->getRHS(), SizeVar)) {
        Found = true;
        return false;
      }
    }
    return true;
  }

  static bool isDeclRefToVar(const Expr *E, const VarDecl *V) {
    E = E->IgnoreParenImpCasts();
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E);
    if (!DRE)
      return false;
    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    return VD == V;
  }
};

// Visitor to find an IfStmt whose condition checks SizeVar (e.g. n > nOut).
class CheckedIfFinder : public RecursiveASTVisitor<CheckedIfFinder> {
public:
  const VarDecl *SizeVar;
  bool Found = false;

  explicit CheckedIfFinder(const VarDecl *SV) : SizeVar(SV) {}

  bool VisitIfStmt(IfStmt *IS) {
    if (IS->getCond()) {
      SizeComparisonFinder Finder(SizeVar);
      Finder.TraverseStmt(IS->getCond());
      if (Finder.Found) {
        Found = true;
        return false; // stop traversal
      }
    }
    return true;
  }
};

// Find the innermost enclosing loop (while, for, do) of a statement.
const Stmt *findEnclosingLoop(const Stmt *S, CheckerContext &C) {
  if (!S)
    return nullptr;
  if (const WhileStmt *WS = findSpecificTypeInParents<WhileStmt>(S, C))
    return WS;
  if (const ForStmt *FS = findSpecificTypeInParents<ForStmt>(S, C))
    return FS;
  if (const DoStmt *DS = findSpecificTypeInParents<DoStmt>(S, C))
    return DS;
  return nullptr;
}

// Get the body of a loop statement.
const Stmt *getLoopBody(const Stmt *Loop) {
  if (const WhileStmt *WS = dyn_cast<WhileStmt>(Loop))
    return WS->getBody();
  if (const ForStmt *FS = dyn_cast<ForStmt>(Loop))
    return FS->getBody();
  if (const DoStmt *DS = dyn_cast<DoStmt>(Loop))
    return DS->getBody();
  return nullptr;
}

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow", "Out-of-bounds write")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  bool hasCheckedComparisonInLoop(const Stmt *LoopBody,
                                  const VarDecl *SizeVar) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // 1. Identify memset call.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr || !ExprHasName(OriginExpr, "memset", C))
    return;

  // 2. Ensure we are inside a parser_input role function.
  const LocationContext *LC = Call.getLocationContext();
  if (!LC)
    return;
  const Decl *D = LC->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || !knighter::declIsRole(FD, "parser_input"))
    return;

  // 3. Extract the size argument (3rd argument of memset).
  if (Call.getNumArgs() < 3)
    return;
  const Expr *SizeArg = Call.getArgExpr(2);
  if (!SizeArg)
    return;
  SizeArg = SizeArg->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(SizeArg);
  if (!DRE)
    return;
  const VarDecl *SizeVar = dyn_cast<VarDecl>(DRE->getDecl());
  if (!SizeVar)
    return;

  // 4. The size variable must be an integer with bit width < 64 (e.g. int).
  QualType QT = SizeVar->getType();
  if (!QT->isIntegerType())
    return;
  if (C.getASTContext().getTypeSize(QT) >= 64)
    return;
  if (!QT->isSignedIntegerType())
    return;

  // 5. Collect all assignments to the size variable inside the function.
  AssignmentCollector Collector(SizeVar);
  if (const Stmt *Body = FD->getBody()) {
    Collector.TraverseStmt(const_cast<Stmt *>(Body));
  }

  // 6. Find the loop that contains the memset call.
  const Stmt *MemsetLoop = findEnclosingLoop(OriginExpr, C);

  // 7. Check each assignment for the unchecked accumulation pattern.
  for (const Stmt *AssignStmt : Collector.Assignments) {
    const BinaryOperator *BO = dyn_cast<BinaryOperator>(AssignStmt);
    if (!BO)
      continue;

    BinaryOperator::Opcode Op = BO->getOpcode();
    bool isAddAssign = (Op == BO_AddAssign);
    bool isAssignWithAdd = false;
    if (Op == BO_Assign) {
      const BinaryOperator *RHSBO =
          dyn_cast<BinaryOperator>(BO->getRHS()->IgnoreParenImpCasts());
      if (RHSBO && RHSBO->getOpcode() == BO_Add)
        isAssignWithAdd = true;
    }
    if (!isAddAssign && !isAssignWithAdd)
      continue;

    const Expr *RHS = BO->getRHS();
    if (!RHS)
      continue;

    // The right-hand side must contain a multiplication (untrusted size accumulation).
    MulFinder MF;
    MF.TraverseStmt(const_cast<Expr *>(RHS));
    if (!MF.Found)
      continue;

    // Find the innermost loop containing the accumulation.
    const Stmt *AssignLoop = findEnclosingLoop(AssignStmt, C);
    if (!AssignLoop)
      continue;

    // The memset must not be inside the same accumulation loop.
    if (AssignLoop == MemsetLoop)
      continue;

    // Check whether the accumulation loop contains an explicit bounds check
    // (e.g. `if (n > nOut) return -1;`).
    const Stmt *LoopBody = getLoopBody(AssignLoop);
    if (!LoopBody)
      continue;
    if (hasCheckedComparisonInLoop(LoopBody, SizeVar))
      continue;

    // Report the bug.
    PathDiagnosticLocation Loc = PathDiagnosticLocation::createBegin(
        OriginExpr, C.getSourceManager(), C.getLocationContext());
    auto report = std::make_unique<BasicBugReport>(
        *BT,
        "Potential integer overflow in untrusted size accumulation leading to "
        "out-of-bounds write",
        Loc);
    report->addRange(Call.getSourceRange());
    C.emitReport(std::move(report));
    break; // one report per memset is enough
  }
}

bool SAGenTestChecker::hasCheckedComparisonInLoop(
    const Stmt *LoopBody, const VarDecl *SizeVar) const {
  if (!LoopBody)
    return false;
  CheckedIfFinder Finder(SizeVar);
  Finder.TraverseStmt(const_cast<Stmt *>(LoopBody));
  return Finder.Found;
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in untrusted size accumulation leading to "
      "out-of-bounds write",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["kvvfsDecode"], "description": "Function that decodes untrusted or encoded input into a buffer; its input parameters are considered untrusted."}
}
*/
