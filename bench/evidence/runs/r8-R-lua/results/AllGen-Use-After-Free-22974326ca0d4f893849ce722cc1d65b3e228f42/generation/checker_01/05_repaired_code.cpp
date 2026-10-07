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

#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing GC anchor", "GC")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  bool containsAnchor(const Stmt *S, const VarDecl *VD, CheckerContext &C) const;
  bool containsWeakReferenceLookupBefore(const Stmt *S, const Expr *CE,
                                         CheckerContext &C) const;
  bool hasRoleCall(const CallExpr *CE, const char *Role,
                   CheckerContext &C) const;
  bool isArgOfVar(const Expr *Arg, const VarDecl *VD, CheckerContext &C) const;
};
} // namespace

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Step 1: Check if this is a GC-triggering call
  if (!knighter::callIsRole(Call, "gc_triggering_call"))
    return;

  const Expr *CE = Call.getOriginExpr();
  if (!CE)
    return;

  // Step 2: Find weakly referenced object argument
  const VarDecl *WeakVar = nullptr;
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *Arg = Call.getArgExpr(i);
    if (!Arg)
      continue;
    const Expr *ArgNoCasts = Arg->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(ArgNoCasts)) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (knighter::isRole("weakly_referenced_object", VD->getName())) {
          WeakVar = VD;
          break;
        }
      }
    }
  }
  if (!WeakVar)
    return;

  // Step 3: Find enclosing CompoundStmt
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(CE, C);
  if (!CS)
    return;

  // Step 4: Check for preceding anchor in the same CompoundStmt
  const SourceManager &SM = C.getSourceManager();
  SourceLocation CEBegin = CE->getSourceRange().getBegin();
  bool anchored = false;
  for (const Stmt *S : CS->body()) {
    if (SM.isBeforeInTranslationUnit(S->getSourceRange().getBegin(), CEBegin)) {
      if (containsAnchor(S, WeakVar, C)) {
        anchored = true;
        break;
      }
    }
  }
  if (anchored)
    return;

  // Step 5: (Optional) Check for weak_reference_lookup before CE in the function
  const LocationContext *LC = C.getLocationContext();
  const Decl *D = LC->getDecl();
  if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
    if (const Stmt *Body = FD->getBody()) {
      if (!containsWeakReferenceLookupBefore(Body, CE, C)) {
        return; // No weak reference lookup, so no bug
      }
    }
  }

  // Step 6: Report bug
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "GC object may be collected during GC-triggering call without anchoring",
      N);
  Report->addRange(CE->getSourceRange());
  C.emitReport(std::move(Report));
}

bool SAGenTestChecker::containsAnchor(const Stmt *S, const VarDecl *VD,
                                      CheckerContext &C) const {
  if (!S)
    return false;
  if (const CallExpr *CE = dyn_cast<CallExpr>(S)) {
    if (hasRoleCall(CE, "gc_anchor", C)) {
      // Check if any argument references VD
      for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
        const Expr *Arg = CE->getArg(i);
        if (isArgOfVar(Arg, VD, C)) {
          return true;
        }
      }
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsAnchor(Child, VD, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::hasRoleCall(const CallExpr *CE, const char *Role,
                                   CheckerContext &C) const {
  if (!CE)
    return false;
  // Try direct callee
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    if (knighter::isRole(Role, FD->getName()))
      return true;
  }
  // Fallback: check source text for any role name
  for (const std::string &Name : knighter::roleNames(Role)) {
    if (ExprHasName(CE, Name, C))
      return true;
  }
  return false;
}

bool SAGenTestChecker::isArgOfVar(const Expr *Arg, const VarDecl *VD,
                                  CheckerContext &C) const {
  if (!Arg)
    return false;
  const Expr *ArgNoCasts = Arg->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(ArgNoCasts)) {
    if (DRE->getDecl() == VD)
      return true;
  }
  // Fallback: check source text contains variable name
  return ExprHasName(Arg, VD->getName(), C);
}

bool SAGenTestChecker::containsWeakReferenceLookupBefore(
    const Stmt *S, const Expr *CE, CheckerContext &C) const {
  if (!S)
    return false;
  const SourceManager &SM = C.getSourceManager();
  SourceLocation CEBegin = CE->getSourceRange().getBegin();

  if (const CallExpr *Call = dyn_cast<CallExpr>(S)) {
    if (hasRoleCall(Call, "weak_reference_lookup", C)) {
      // Check if this call is before CE
      SourceLocation CallBegin = Call->getSourceRange().getBegin();
      if (SM.isBeforeInTranslationUnit(CallBegin, CEBegin)) {
        return true;
      }
    }
  }
  for (const Stmt *Child : S->children()) {
    if (containsWeakReferenceLookupBefore(Child, CE, C))
      return true;
  }
  return false;
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing GC anchor before GC-triggering call",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "gc_triggering_call": {"names": ["luaH_finishset"], "description": "call that can allocate memory and trigger an emergency garbage collection"},
  "gc_anchor": {"names": ["sethvalue2s"], "description": "function/macro that roots a GC object on the Lua stack before a GC-triggering call"},
  "weakly_referenced_object": {"names": ["h"], "description": "local variable holding the GC object (table) that may be weakly referenced and is updated after a GC-triggering call"},
  "weak_reference_lookup": {"names": ["fasttm", "luaT_gettmbyobj"], "description": "retrieves a metamethod value from a possibly weak metatable"},
  "use_after_free_site": {"names": ["invalidateTMcache", "luaC_barrierback"], "description": "operations that access the object after the GC-triggering call"}
}
*/
