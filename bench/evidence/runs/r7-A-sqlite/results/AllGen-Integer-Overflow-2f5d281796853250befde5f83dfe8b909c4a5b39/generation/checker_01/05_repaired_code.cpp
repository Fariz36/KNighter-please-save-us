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

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

#include <functional>
#include <memory>
#include <set>

using namespace clang;
using namespace ento;
using namespace taint;

// The set of VarDecls that are narrow integer types used (potentially) as
// loop counters / accumulators.
REGISTER_SET_WITH_PROGRAMSTATE(NarrowCounterSet, const VarDecl *)

namespace {

// ---------------------------------------------------------------------------
// Helper: is the given type a "narrow" integer type (int, unsigned, short).
// i64 / long long / unsigned long long are considered wide and safe.
// ---------------------------------------------------------------------------
static bool isNarrowIntegerType(QualType QT) {
  if (!QT->isIntegerType())
    return false;
  unsigned Size = QT->getAs<BuiltinType>()
                      ? QT.getTypePtr()->getAs<BuiltinType>()
                            ? QT->getAs<BuiltinType>()->getKind()
                            : 0
                      : 0;
  (void)Size;
  if (const BuiltinType *BT = QT->getAs<BuiltinType>()) {
    switch (BT->getKind()) {
      case BuiltinType::Bool:
      case BuiltinType::Char_S:
      case BuiltinType::Char_U:
      case BuiltinType::SChar:
      case BuiltinType::UChar:
      case BuiltinType::Short:
      case BuiltinType::UShort:
      case BuiltinType::Int:
      case BuiltinType::UInt:
        return true;
      default:
        return false;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Check whether an expression (used as a loop bound or an assert expression)
// references a potentially very-large quantity such as SQLITE_MAX_LENGTH
// or is derived from an i64 variable (nOut).
// ---------------------------------------------------------------------------
static bool referencesLargeBound(const Expr *E, ASTContext &Ctx) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  // Direct reference to an identifier text containing SQLITE_MAX_LENGTH.
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    StringRef Name = DRE->getDecl()->getName();
    if (Name == "SQLITE_MAX_LENGTH" || Name == "SQLITE_LIMIT_LENGTH")
      return true;
  }

  // Integer literal > INT_MAX indicates a large bound.
  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
    const llvm::APInt &V = IL->getValue();
    if (V.getBitWidth() > 32 || V.getSExtValue() > INT32_MAX)
      return true;
  }

  // Recursively look at sub expressions.
  for (const Stmt *Child : E->children()) {
    if (const Expr *CE = dyn_cast<Expr>(Child)) {
      if (referencesLargeBound(CE, Ctx))
        return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Check whether an expression contains a reference to any VarDecl in the
// NarrowCounterSet (i.e. a narrow-typed accumulator/counter).
// ---------------------------------------------------------------------------
static bool usesNarrowCounter(const Expr *E,
                              const std::set<const VarDecl *> &NarrowCounters) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (NarrowCounters.count(VD))
        return true;
    }
  }
  for (const Stmt *Child : E->children()) {
    if (const Expr *CE = dyn_cast<Expr>(Child)) {
      if (usesNarrowCounter(CE, NarrowCounters))
        return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Check whether an expression contains an arithmetic operator (add/sub/mul)
// which is the actual overflow-prone point.
// ---------------------------------------------------------------------------
static bool hasArithmeticOp(const Expr *E) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    switch (BO->getOpcode()) {
      case BO_Add:
      case BO_Sub:
      case BO_Mul:
        return true;
      default:
        break;
    }
  }
  for (const Stmt *Child : E->children()) {
    if (const Expr *CE = dyn_cast<Expr>(Child)) {
      if (hasArithmeticOp(CE))
        return true;
    }
  }
  return false;
}

class SAGenTestChecker
    : public Checker<check::ASTCodeBody,
                     check::PreStmt<ForStmt>,
                     check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;
  mutable std::set<const VarDecl *> NarrowCounters;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Narrow loop counter may overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

  void checkPreStmt(const ForStmt *FS, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &Ctx) const;

private:
  void reportOverflow(const Stmt *S, const VarDecl *VD, CheckerContext &C,
                      StringRef Msg) const;

  const VarDecl *findNarrowVD(const Expr *E) const;
};

// ---------------------------------------------------------------------------
// Collect narrow integer VarDecls at function body level. We populate a set
// stored in the program state that subsequent callbacks consult.
// ---------------------------------------------------------------------------
void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  // We record which VarDecls look like loop counters / accumulators so that
  // we only flag the interesting cases. We only care about names that are
  // typical counter names to avoid false positives on ordinary variables.
  for (const Decl *Child : FD->decls()) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(Child)) {
      QualType QT = VD->getType();
      if (!isNarrowIntegerType(QT))
        continue;
      StringRef Name = VD->getName();
      // Only track variables typically used as loop counters/accumulators.
      if (Name == "i" || Name == "j" || Name == "k" || Name == "n" ||
          Name == "cnt" || Name == "count" || Name == "idx" ||
          Name == "index" || Name == "len" || Name == "size") {
        NarrowCounters.insert(VD);
      }
    }
  }
}

const VarDecl *SAGenTestChecker::findNarrowVD(const Expr *E) const {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (NarrowCounters.count(VD))
        return VD;
    }
  }
  for (const Stmt *Child : E->children()) {
    if (const Expr *CE = dyn_cast<Expr>(Child)) {
      if (const VarDecl *VD = findNarrowVD(CE))
        return VD;
    }
  }
  return nullptr;
}

void SAGenTestChecker::checkPreStmt(const ForStmt *FS,
                                    CheckerContext &C) const {
  const Expr *Cond = FS->getCond();
  if (!Cond)
    return;

  // Condition form: `i <= loopLimit` where loopLimit is later computed
  // from a large bound (e.g. derived from nStr / SQLITE_MAX_LENGTH).
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenImpCasts());
  if (!BO)
    return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();

  // Identify the narrow counter in the condition.
  const VarDecl *NarrowVD = nullptr;
  if (const DeclRefExpr *DRE =
          dyn_cast<DeclRefExpr>(LHS->IgnoreParenImpCasts())) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (NarrowCounters.count(VD))
        NarrowVD = VD;
    }
  }
  if (!NarrowVD)
    return;

  // Now check whether the bound (RHS) or something in the loop body suggests
  // an accumulation into an i64 that could exceed the narrow counter range.
  bool suspicious = false;
  if (FS->getBody()) {
    for (const Stmt *S : FS->getBody()->children()) {
      if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
        for (const Decl *D : DS->decls()) {
          if (const VarDecl *VD = dyn_cast<VarDecl>(D)) {
            QualType QT = VD->getType();
            if (QT->isIntegerType()) {
              ASTContext &Ctx = C.getASTContext();
              unsigned NumBits = Ctx.getTypeSize(QT);
              if (NumBits > 32) {
                // i64 accumulator present, likely nOut.
                suspicious = true;
              }
            }
          }
        }
      }
      if (const Expr *E = dyn_cast<Expr>(S)) {
        if (referencesLargeBound(E, C.getASTContext()))
          suspicious = true;
      }
    }
  }

  // Also look at the outer scope for SQLITE_MAX_LENGTH references: in the
  // buggy function, the loop body computes nOut (i64) via repeated use of
  // `nRep - nPattern`, and later asserts on `j+nStr-i+1<=nOut`.
  // We conservatively taint the narrow counter as a potential overflow site
  // if we see any large-bound arithmetic in the same loop body.
  if (!suspicious) {
    // Additional signal: the loop bound expression contains subtraction of
    // two narrow-or-i64 operands (nStr - nPattern) that could be large.
    if (const BinaryOperator *RBO =
            dyn_cast<BinaryOperator>(RHS->IgnoreParenImpCasts())) {
      if (RBO->getOpcode() == BO_Sub)
        suspicious = true;
    }
  }

  if (!suspicious)
    return;

  // Because the loop counter is narrow and the loop reaches a bound derived
  // from a large value, its value can overflow if the bound exceeds INT_MAX.
  reportOverflow(FS, NarrowVD, C,
                 "Loop counter of narrow integer type may overflow");
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &Ctx) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  // Pattern: `if( nOut-1>db->aLimit[SQLITE_LIMIT_LENGTH] )` guarded inside
  // an accumulation loop, and later `assert( j+nStr-i+1<=nOut )` uses a
  // narrow counter. We detect here when the branch condition references
  // a narrow counter in combination with arithmetic, as an additional
  // overflow-prone site.
  if (!usesNarrowCounter(CondE, NarrowCounters))
    return;
  if (!hasArithmeticOp(CondE))
    return;

  // Only report if the condition also references a large bound (SQLITE_MAX_LENGTH
  // / SQLITE_LIMIT_LENGTH) or a wide-i64 accumulator that could make the narrow
  // operand overflow.
  ASTContext &CtxAST = Ctx.getASTContext();
  bool largeBound = referencesLargeBound(CondE, CtxAST);

  // Also consider a comparison where both sides are arithmetic involving a
  // narrow counter and a potentially larger value.
  const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE->IgnoreParenImpCasts());
  if (!largeBound && BO) {
    // Look for expression comparing against an array subscript (aLimit[...])
    // which in SQLite holds the LENGTH limit (large).
    std::function<bool(const Expr *)> hasArraySub =
        [&](const Expr *E) -> bool {
      if (!E)
        return false;
      E = E->IgnoreParenImpCasts();
      if (isa<ArraySubscriptExpr>(E))
        return true;
      for (const Stmt *Child : E->children()) {
        if (const Expr *CE = dyn_cast<Expr>(Child)) {
          if (hasArraySub(CE))
            return true;
        }
      }
      return false;
    };
    if (hasArraySub(BO->getRHS()) || hasArraySub(BO->getLHS()))
      largeBound = true;
  }

  if (!largeBound)
    return;

  // Locate the offending narrow counter VarDecl.
  const VarDecl *OffendingVD = findNarrowVD(CondE);
  if (!OffendingVD)
    return;

  reportOverflow(Condition, OffendingVD, Ctx,
                 "Arithmetic on narrow loop counter may overflow "
                 "against large bound");
}

void SAGenTestChecker::reportOverflow(const Stmt *S, const VarDecl *VD,
                                      CheckerContext &C,
                                      StringRef Msg) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  report->addRange(S->getSourceRange());
  if (VD)
    report->addNote("'" + VD->getName().str() +
                        "' declared here with a narrow integer type",
                    PathDiagnosticLocation::createBegin(
                        VD, C.getSourceManager(),
                        C.getLocationContext()));
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potential integer overflow when narrow integer loop "
      "counters/accumulators are used against large bounds "
      "(e.g. SQLITE_MAX_LENGTH)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
