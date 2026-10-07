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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

static TaintTagType AllocTaint = 101;

REGISTER_MAP_WITH_PROGRAMSTATE(FieldFreedMap, const FieldDecl *, bool)

namespace {
class SAGenTestChecker
    : public Checker<check::PostCall, check::PreCall, check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory Leak", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
};
} // end anonymous namespace

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "allocator"))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = RetVal.getAsSymbol();
  if (!Sym)
    return;

  State = addTaint(State, Sym, AllocTaint);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "deallocator"))
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    const Expr *ArgE = Call.getArgExpr(I);
    if (!ArgE)
      continue;

    ArgE = ArgE->IgnoreParenImpCasts();
    if (const MemberExpr *ME = dyn_cast<MemberExpr>(ArgE)) {
      const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
      if (FD && knighter::declIsRole(FD, "owned_pointer_field")) {
        State = State->set<FieldFreedMap>(FD, true);
        Changed = true;
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LocR = Loc.getAsRegion();
  if (!LocR)
    return;

  const FieldRegion *FR = LocR->getAs<FieldRegion>();
  if (!FR)
    return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD || !knighter::declIsRole(FD, "owned_pointer_field"))
    return;

  const Decl *D = C.getLocationContext()->getDecl();
  const NamedDecl *ND = dyn_cast<NamedDecl>(D);
  if (!ND || !knighter::declIsRole(ND, "setter"))
    return;

  SymbolRef Sym = Val.getAsSymbol();
  if (!Sym || !isTainted(State, Sym, AllocTaint))
    return;

  const bool *Freed = State->get<FieldFreedMap>(FD);
  if (!Freed || !*Freed) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (N) {
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "Potential leak: overwriting owned pointer field with new allocation "
          "without freeing previous value",
          N);
      if (StoreE)
        Report->addRange(StoreE->getSourceRange());
      C.emitReport(std::move(Report));
    }
  }

  State = State->set<FieldFreedMap>(FD, false);
  C.addTransition(State);
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects overwriting an owned pointer field with a new allocation "
      "without freeing the previous value",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "setter": {"names": ["xmlCtxtSetSaxHandler"], "description": "function that sets a field on a context object"},
  "allocator": {"names": ["xmlMalloc"], "description": "memory allocation function returning a pointer to newly allocated memory"},
  "owned_pointer_field": {"names": ["sax"], "description": "struct field that owns a heap allocation and must be freed before being overwritten"},
  "deallocator": {"names": ["xmlFree"], "description": "memory deallocation function"},
  "copier": {"names": ["memcpy"], "description": "function that copies data into an existing allocation"}
}
*/
