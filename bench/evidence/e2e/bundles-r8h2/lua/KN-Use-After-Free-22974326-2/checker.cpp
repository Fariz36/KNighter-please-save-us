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
#include "clang/AST/Type.h"
#include "clang/AST/Decl.h"
#include "clang/Lex/Lexer.h"
#include "clang/Basic/SourceManager.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper: check if the expression is a pointer to a type that plays the role
// of a GC-managed object.
static bool isGcManagedPointer(const Expr *Arg) {
  if (!Arg)
    return false;
  QualType Ty = Arg->getType();
  const PointerType *PT = Ty->getAs<PointerType>();
  if (!PT)
    return false;
  QualType Pointee = PT->getPointeeType();
  Pointee = Pointee.getCanonicalType().getUnqualifiedType();
  if (const RecordType *RT = Pointee->getAs<RecordType>()) {
    StringRef Name = RT->getDecl()->getName();
    return knighter::isRole("gc_managed_object", Name);
  }
  return false;
}

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing GC root anchor", "Use After Free")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Only inspect calls to potential GC triggers.
  if (!knighter::callIsRole(Call, "potential_gc_trigger"))
    return;

  const Stmt *CallStmt = Call.getOriginExpr();
  if (!CallStmt)
    return;

  // Find the innermost enclosing CompoundStmt.
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(CallStmt, C);
  if (!CS)
    return;

  const SourceManager &SM = C.getSourceManager();
  const LangOptions &LangOpts = C.getLangOpts();

  // Locate the direct child statement of CS that contains the call.
  const Stmt *CurrentStmt = nullptr;
  for (const Stmt *S : CS->body()) {
    if (S->getSourceRange().fullyContains(CallStmt->getSourceRange())) {
      CurrentStmt = S;
      break;
    }
  }
  if (!CurrentStmt)
    return;

  // Find its index in the compound statement.
  auto Body = CS->body_begin();
  unsigned CurrentIdx = 0;
  bool Found = false;
  for (unsigned i = 0; i < CS->size(); ++i) {
    if (Body[i] == CurrentStmt) {
      CurrentIdx = i;
      Found = true;
      break;
    }
  }
  if (!Found)
    return;

  // Check each argument for a GC-managed pointer.
  for (unsigned I = 0, E = Call.getNumArgs(); I != E; ++I) {
    const Expr *Arg = Call.getArgExpr(I);
    if (!Arg)
      continue;
    if (!isGcManagedPointer(Arg))
      continue;

    // Get the source text of the argument (object anchor key).
    CharSourceRange ArgRange = CharSourceRange::getTokenRange(Arg->getSourceRange());
    StringRef ArgText = Lexer::getSourceText(ArgRange, SM, LangOpts);
    if (ArgText.empty())
      continue;

    // Walk backward over previous statements in the same compound statement.
    bool Anchored = false;
    for (unsigned i = 0; i < CurrentIdx; ++i) {
      const Stmt *Prev = Body[i];
      if (!Prev)
        continue;
      StringRef PrevText = Lexer::getSourceText(
          CharSourceRange::getTokenRange(Prev->getSourceRange()), SM, LangOpts);
      if (PrevText.empty())
        continue;

      bool HasAnchor = false;
      for (const auto &AnchorName : knighter::roleNames("gc_root_anchor")) {
        if (PrevText.contains(AnchorName)) {
          HasAnchor = true;
          break;
        }
      }
      if (HasAnchor && PrevText.contains(ArgText)) {
        Anchored = true;
        break;
      }
    }

    if (!Anchored) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "GC-managed object passed to potential GC trigger without GC root anchor; possible use-after-free.",
          N);
      Report->addRange(Arg->getSourceRange());
      C.emitReport(std::move(Report));
      return; // Stop after first unanchored argument.
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects GC-managed objects passed to potential GC triggers without a preceding GC root anchor",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "gc_managed_object": {"names": ["Table"], "description": "object managed by a garbage collector; its lifetime is not tied to C scopes"},
  "potential_gc_trigger": {"names": ["luaH_finishset"], "description": "operation that may trigger an emergency garbage collection, reclaiming unreachable objects"},
  "gc_root_anchor": {"names": ["sethvalue2s"], "description": "operation that makes a GC-managed object visible to the collector as a root, protecting it from collection"},
  "weak_reference_container": {"names": ["__mode"], "description": "field or container that holds weak references, not keeping objects alive"},
  "use_after_free_use": {"names": ["invalidateTMcache", "luaC_barrierback"], "description": "operation that uses a pointer to a GC-managed object after a potential collection could have freed it"}
}
*/
