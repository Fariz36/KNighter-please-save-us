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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper: check if an expression is a DeclRefExpr referring to a given VarDecl.
static bool isDeclRefToVar(const Expr *E, const VarDecl *VD) {
  if (!E)
    return false;
  E = E->IgnoreImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    return DRE->getDecl() == VD;
  return false;
}

// Helper: recursively search for a statement containing a return/break/continue.
static bool containsReturnBreakContinue(const Stmt *S) {
  if (!S)
    return false;
  if (isa<ReturnStmt>(S) || isa<BreakStmt>(S) || isa<ContinueStmt>(S))
    return true;
  for (const Stmt *Child : S->children()) {
    if (containsReturnBreakContinue(Child))
      return true;
  }
  return false;
}

// Helper: recursively search for the accumulation pattern inside the inner loop.
static bool containsAccumulation(const Stmt *S, const VarDecl *CountVar,
                                 const VarDecl *MultVar) {
  if (!S)
    return false;
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_AddAssign || Op == BO_Add) {
      const Expr *LHS = BO->getLHS();
      if (isDeclRefToVar(LHS, CountVar)) {
        const Expr *RHS = BO->getRHS();
        if (const auto *Mul = dyn_cast<BinaryOperator>(RHS->IgnoreImpCasts())) {
          if (Mul->getOpcode() == BO_Mul) {
            const Expr *Op0 = Mul->getLHS();
            const Expr *Op1 = Mul->getRHS();
            if (isDeclRefToVar(Op0, MultVar) || isDeclRefToVar(Op1, MultVar))
              return true;
          }
        }
      }
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsAccumulation(Child, CountVar, MultVar))
      return true;
  }
  return false;
}

// Helper: recursively search for the multiplier update pattern.
static bool containsMultiplierUpdate(const Stmt *S, const VarDecl *MultVar) {
  if (!S)
    return false;
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_MulAssign || Op == BO_Mul) {
      const Expr *LHS = BO->getLHS();
      if (isDeclRefToVar(LHS, MultVar)) {
        const Expr *RHS = BO->getRHS();
        if (isa<IntegerLiteral>(RHS->IgnoreImpCasts()))
          return true;
      }
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsMultiplierUpdate(Child, MultVar))
      return true;
  }
  return false;
}

// Helper: recursively search for the overflow guard (n > nOut) inside a
// statement. Returns true if a matching IfStmt with a terminating
// then-branch is found.
static bool containsGuard(const Stmt *S, const VarDecl *CountVar,
                          const VarDecl *CapVar) {
  if (!S)
    return false;
  if (const auto *If = dyn_cast<IfStmt>(S)) {
    const Expr *Cond = If->getCond()->IgnoreImpCasts();
    if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
      if (BO->getOpcode() == BO_GT) {
        const Expr *LHS = BO->getLHS();
        const Expr *RHS = BO->getRHS();
        if (isDeclRefToVar(LHS, CountVar) && isDeclRefToVar(RHS, CapVar)) {
          const Stmt *Then = If->getThen();
          if (Then && containsReturnBreakContinue(Then))
            return true;
        }
      }
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsGuard(Child, CountVar, CapVar))
      return true;
  }
  return false;
}

// Helper: recursively search for the bounds check (j+n > nOut) before the
// memset call. If found, fills CapVar and OffsetVar and returns true.
static bool findBoundsCheck(const Stmt *S, const CallExpr *CE,
                            CheckerContext &C, const VarDecl *CountVar,
                            const VarDecl *&CapVar,
                            const VarDecl *&OffsetVar) {
  if (!S)
    return false;
  if (const auto *If = dyn_cast<IfStmt>(S)) {
    if (C.getSourceManager().isBeforeInTranslationUnit(
            If->getBeginLoc(), CE->getBeginLoc())) {
      const Expr *Cond = If->getCond()->IgnoreImpCasts();
      if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
        if (BO->getOpcode() == BO_GT) {
          const Expr *LHS = BO->getLHS()->IgnoreImpCasts();
          const Expr *RHS = BO->getRHS()->IgnoreImpCasts();
          if (const auto *RHS_DRE = dyn_cast<DeclRefExpr>(RHS)) {
            if (const auto *CapVD =
                    dyn_cast<VarDecl>(RHS_DRE->getDecl())) {
              if (knighter::isRole("output_capacity", CapVD->getName())) {
                if (const auto *Add = dyn_cast<BinaryOperator>(LHS)) {
                  if (Add->getOpcode() == BO_Add) {
                    const Expr *AddLHS = Add->getLHS()->IgnoreImpCasts();
                    const Expr *AddRHS = Add->getRHS()->IgnoreImpCasts();
                    const VarDecl *OffsetVD = nullptr;
                    if (isDeclRefToVar(AddLHS, CountVar)) {
                      if (const auto *DRE = dyn_cast<DeclRefExpr>(AddRHS))
                        OffsetVD = dyn_cast<VarDecl>(DRE->getDecl());
                    } else if (isDeclRefToVar(AddRHS, CountVar)) {
                      if (const auto *DRE = dyn_cast<DeclRefExpr>(AddLHS))
                        OffsetVD = dyn_cast<VarDecl>(DRE->getDecl());
                    }
                    if (OffsetVD &&
                        knighter::isRole("output_offset", OffsetVD->getName())) {
                      CapVar = CapVD;
                      OffsetVar = OffsetVD;
                      return true;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  for (const Stmt *Child : S->children()) {
    if (findBoundsCheck(Child, CE, C, CountVar, CapVar, OffsetVar))
      return true;
  }
  return false;
}

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Potential Integer Overflow in Decoded Length",
                       "Memory safety")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee || Callee->getName() != "memset")
    return;

  const Expr *CE = Call.getOriginExpr();
  if (!CE)
    return;
  const CallExpr *CallE = dyn_cast<CallExpr>(CE);
  if (!CallE || CallE->getNumArgs() != 3)
    return;

  // 3.2 Extract the size argument and verify it is a narrow decoded length.
  const Expr *SizeExpr = CallE->getArg(2)->IgnoreImpCasts();
  const auto *SizeDRE = dyn_cast<DeclRefExpr>(SizeExpr);
  if (!SizeDRE)
    return;
  const auto *CountVar = dyn_cast<VarDecl>(SizeDRE->getDecl());
  if (!CountVar)
    return;
  if (!knighter::isRole("decoded_length", CountVar->getName()))
    return;
  if (!knighter::isRole("narrow_integer", CountVar->getType().getAsString()))
    return;

  // 3.3 Locate the enclosing block and the inner decoding loop.
  const CompoundStmt *Body = findSpecificTypeInParents<CompoundStmt>(CallE, C);
  if (!Body)
    return;

  const WhileStmt *InnerWhile = nullptr;
  for (const Stmt *S : Body->body()) {
    if (const auto *WS = dyn_cast<WhileStmt>(S)) {
      InnerWhile = WS;
      break;
    }
  }
  if (!InnerWhile)
    return;

  // 3.4 Verify the accumulation and multiplier update.
  // Find MultVar first.
  const VarDecl *MultVar = nullptr;
  for (const Stmt *S : Body->body()) {
    if (const auto *DS = dyn_cast<DeclStmt>(S)) {
      for (const Decl *D : DS->decls()) {
        if (const auto *VD = dyn_cast<VarDecl>(D)) {
          if (knighter::isRole("place_value_multiplier", VD->getName()) &&
              knighter::isRole("narrow_integer",
                               VD->getType().getAsString())) {
            MultVar = VD;
            break;
          }
        }
      }
      if (MultVar)
        break;
    }
  }
  if (!MultVar)
    return;

  const Stmt *InnerBody = InnerWhile->getBody();
  if (!containsAccumulation(InnerBody, CountVar, MultVar))
    return;
  if (!containsMultiplierUpdate(InnerBody, MultVar))
    return;

  // 3.5 Verify the bounds check.
  const VarDecl *CapVar = nullptr;
  const VarDecl *OffsetVar = nullptr;
  if (!findBoundsCheck(Body, CallE, C, CountVar, CapVar, OffsetVar))
    return;

  // 3.6 Check for the missing overflow guard.
  if (containsGuard(InnerBody, CountVar, CapVar))
    return;

  // 3.7 Report the bug.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential integer overflow in decoded length before bounds check; "
      "narrow integer can wrap and bypass capacity check.",
      N);
  Report->addRange(CallE->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in decoded length before bounds check",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "decoded_length": {"names": ["n"], "description": "integer variable holding a decoded length/count from untrusted input"},
  "place_value_multiplier": {"names": ["mult"], "description": "integer variable holding a place-value multiplier in base-N decoding"},
  "output_capacity": {"names": ["nOut"], "description": "integer parameter giving the capacity of the output buffer"},
  "output_offset": {"names": ["j"], "description": "integer variable holding the current write offset in the output buffer"},
  "narrow_integer": {"names": ["int"], "description": "32-bit or narrower signed integer type"},
  "wide_integer": {"names": ["sqlite3_int64"], "description": "64-bit integer type used to prevent overflow"},
  "untrusted_input": {"names": ["a", "aIn"], "description": "pointer/array parameter holding untrusted encoded input"}
}
*/
