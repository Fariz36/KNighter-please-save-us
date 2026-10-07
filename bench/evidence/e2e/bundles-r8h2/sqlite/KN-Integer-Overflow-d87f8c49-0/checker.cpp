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
#include "clang/AST/Decl.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"

#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper: does the statement subtree contain a DeclRefExpr to a declaration
// that plays the given role?
static bool containsDeclRefToRole(const Stmt *S, StringRef Role) {
  if (!S)
    return false;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (const auto *ND = dyn_cast<NamedDecl>(DRE->getDecl())) {
      if (knighter::declIsRole(ND, Role))
        return true;
    }
  }

  for (const Stmt *Child : S->children()) {
    if (containsDeclRefToRole(Child, Role))
      return true;
  }
  return false;
}

// Helper: does the statement subtree contain a DeclRefExpr to the given
// VarDecl?
static bool containsDeclRefToVar(const Stmt *S, const VarDecl *VD) {
  if (!S || !VD)
    return false;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (DRE->getDecl() == VD)
      return true;
  }

  for (const Stmt *Child : S->children()) {
    if (containsDeclRefToVar(Child, VD))
      return true;
  }
  return false;
}

// Helper: does the source text of the statement contain any name associated
// with the given role?
static bool stmtSourceContainsRole(const Stmt *S, StringRef Role,
                                   ASTContext &Ctx) {
  if (!S)
    return false;

  SourceRange SR = S->getSourceRange();
  if (SR.isInvalid())
    return false;

  const SourceManager &SM = Ctx.getSourceManager();
  const LangOptions &LangOpts = Ctx.getLangOpts();
  CharSourceRange CR = CharSourceRange::getTokenRange(SR);
  StringRef Text = Lexer::getSourceText(CR, SM, LangOpts);
  if (Text.empty())
    return false;

  for (const auto &Name : knighter::roleNames(Role)) {
    if (Text.contains(Name))
      return true;
  }
  return false;
}

// Match: output_length = (int)(advanced_ptr - base_ptr);
static bool matchVulnerableAssignment(const Stmt *Cur, ASTContext &Ctx,
                                      const VarDecl *&AdvancedVD,
                                      const VarDecl *&OutputVD) {
  const auto *BO = dyn_cast<BinaryOperator>(Cur);
  if (!BO || BO->getOpcode() != BO_Assign)
    return false;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  const auto *LHSDRE = dyn_cast<DeclRefExpr>(LHS);
  if (!LHSDRE)
    return false;

  const auto *VD = dyn_cast<VarDecl>(LHSDRE->getDecl());
  if (!VD || !knighter::declIsRole(VD, "output_length"))
    return false;

  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  const auto *CE = dyn_cast<CastExpr>(RHS);
  if (!CE || CE->getCastKind() != CK_IntegralCast)
    return false;

  if (CE->getType().getCanonicalType() != Ctx.IntTy)
    return false;

  const Expr *SubE = CE->getSubExpr()->IgnoreParenImpCasts();
  const auto *SubBO = dyn_cast<BinaryOperator>(SubE);
  if (!SubBO || SubBO->getOpcode() != BO_Sub)
    return false;

  const Expr *L = SubBO->getLHS()->IgnoreParenImpCasts();
  const Expr *R = SubBO->getRHS()->IgnoreParenImpCasts();

  const auto *DRE = dyn_cast<DeclRefExpr>(L);
  if (!DRE)
    DRE = dyn_cast<DeclRefExpr>(R);
  if (!DRE)
    return false;

  const auto *AVD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!AVD || !AVD->getType()->isPointerType())
    return false;

  AdvancedVD = AVD;
  OutputVD = VD;
  return true;
}

// Match: while (character_count_bound ... ) { ... iterator_advance(advanced_ptr) ... }
static bool matchAdvancingLoop(const Stmt *Prev, ASTContext &Ctx,
                               const VarDecl *AdvancedVD) {
  const auto *WS = dyn_cast<WhileStmt>(Prev);
  if (!WS)
    return false;

  const Expr *Cond = WS->getCond();
  if (!containsDeclRefToRole(Cond, "character_count_bound"))
    return false;

  const Stmt *Body = WS->getBody();
  if (!containsDeclRefToVar(Body, AdvancedVD))
    return false;

  if (!stmtSourceContainsRole(Body, "iterator_advance", Ctx))
    return false;

  return true;
}

class VulnerableAssignmentVisitor
    : public RecursiveASTVisitor<VulnerableAssignmentVisitor> {
  ASTContext &Ctx;
  BugReporter &BR;
  BugType &BT;

public:
  VulnerableAssignmentVisitor(ASTContext &Ctx, BugReporter &BR, BugType &BT)
      : Ctx(Ctx), BR(BR), BT(BT) {}

  bool VisitCompoundStmt(CompoundStmt *CS) {
    if (!CS)
      return true;

    auto It = CS->body_begin();
    if (It == CS->body_end())
      return true;

    const Stmt *Prev = *It++;
    for (; It != CS->body_end(); ++It) {
      const Stmt *Cur = *It;

      const VarDecl *AdvancedVD = nullptr;
      const VarDecl *OutputVD = nullptr;
      if (matchVulnerableAssignment(Cur, Ctx, AdvancedVD, OutputVD) &&
          matchAdvancingLoop(Prev, Ctx, AdvancedVD)) {
        BR.emitReport(std::make_unique<BasicBugReport>(
            BT,
            "Unbounded byte length narrowed to int before append; clamp to "
            "safe maximum",
            PathDiagnosticLocation(Cur, Ctx.getSourceManager(),
                                   nullptr)));
      }

      Prev = Cur;
    }

    return true;
  }
};

} // end anonymous namespace

namespace {
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unbounded byte length narrowed to int",
                       "Integer Overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  ASTContext &Ctx = Mgr.getASTContext();
  VulnerableAssignmentVisitor Visitor(Ctx, BR, *BT);
  Visitor.TraverseStmt(FD->getBody());
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unbounded pointer-difference lengths narrowed to int after "
      "UTF-8 character scanning",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "length_of": {"names": [], "description": "pointer difference measuring the byte length after a UTF-8 character scan"},
  "character_count_bound": {"names": ["precision"], "description": "integer precision bound controlling the number of logical characters scanned"},
  "iterator_advance": {"names": ["SQLITE_SKIP_UTF8"], "description": "macro/function that advances a byte pointer past one UTF-8 character; may advance 1-4 bytes"},
  "output_length": {"names": ["length"], "description": "signed int variable that receives the measured byte length for later append/copy"},
  "narrowing_cast": {"names": [], "description": "C integer cast that narrows the pointer difference to signed int"},
  "safe_cap": {"names": ["MIN"], "description": "macro/function that clamps a value to a safe maximum before narrowing"},
  "buffer_append": {"names": ["sqlite3_str_append"], "description": "function that appends a bounded byte buffer to an output accumulator using a signed int length"}
}
*/

