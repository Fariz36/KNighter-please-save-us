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

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/ADT/DenseSet.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(AllocatedPtrMap, SymbolRef, bool)

namespace {

class SAGenTestChecker
    : public Checker<eval::Call, check::PostCall, check::PreCall, check::Bind,
                     check::ASTDecl<FunctionDecl>> {
  mutable std::unique_ptr<BugType> BT;
  mutable llvm::DenseSet<const RecordDecl *> OwnedRecordTypes;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory Leak", "Memory Management")) {}

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkASTDecl(const FunctionDecl *D, AnalysisManager &Mgr,
                    BugReporter &BR) const;
};

} // end anonymous namespace

bool SAGenTestChecker::evalCall(const CallEvent &Call,
                                CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "allocator"))
    return false;

  const Expr *E = Call.getOriginExpr();
  if (!E)
    return false;

  ProgramStateRef State = C.getState();
  SValBuilder &SVB = C.getSValBuilder();
  unsigned Count = C.blockCount();
  const LocationContext *LCtx = C.getLocationContext();

  SVal RetVal = SVB.getConjuredHeapSymbolVal(E, LCtx, Count);
  if (!RetVal.getAs<Loc>())
    return false;

  State = State->BindExpr(E, C.getLocationContext(), RetVal);
  C.addTransition(State);
  return true;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (knighter::callIsRole(Call, "allocator")) {
    SymbolRef Sym = Call.getReturnValue().getAsSymbol();
    if (Sym) {
      State = State->set<AllocatedPtrMap>(Sym, false);
      C.addTransition(State);
    }
    return;
  }

  if (knighter::callIsRole(Call, "buffer_copy")) {
    if (Call.getNumArgs() == 0)
      return;

    SymbolRef DstSym = Call.getArgSVal(0).getAsSymbol();
    if (!DstSym)
      return;

    const bool *Entry = State->get<AllocatedPtrMap>(DstSym);
    if (Entry) {
      State = State->set<AllocatedPtrMap>(DstSym, true);
      C.addTransition(State);
    }
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "deallocator"))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned I = 0, N = Call.getNumArgs(); I < N; ++I) {
    SymbolRef Sym = Call.getArgSVal(I).getAsSymbol();
    if (Sym)
      State = State->remove<AllocatedPtrMap>(Sym);
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  const FieldRegion *FR = dyn_cast<FieldRegion>(R);
  if (!FR)
    return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD)
    return;

  if (!FD->getType()->isPointerType())
    return;

  const RecordDecl *Parent = FD->getParent();
  if (!Parent || OwnedRecordTypes.count(Parent) == 0)
    return;

  SymbolRef Sym = Val.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  const bool *Entry = State->get<AllocatedPtrMap>(Sym);
  if (!Entry || !*Entry)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential memory leak: overwriting owning pointer field without "
      "freeing previous value",
      N);
  if (S)
    Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkASTDecl(const FunctionDecl *D,
                                    AnalysisManager &Mgr,
                                    BugReporter &BR) const {
  if (!D)
    return;

  if (!knighter::declIsRole(D, "deallocator"))
    return;

  for (const ParmVarDecl *P : D->parameters()) {
    QualType QT = P->getType();
    const PointerType *PT = QT->getAs<PointerType>();
    if (!PT)
      continue;

    QualType Pointee = PT->getPointeeType();
    const RecordType *RT = Pointee->getAs<RecordType>();
    if (!RT)
      continue;

    if (const RecordDecl *RD = RT->getDecl())
      OwnedRecordTypes.insert(RD);
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects overwriting an owning pointer field with a newly allocated "
      "object without freeing the old value",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {
    "names": ["xmlMalloc"],
    "description": "allocates a new dynamically-sized memory block and returns a pointer to it, or NULL on failure"
  },
  "deallocator": {
    "names": ["xmlFreeParserCtxt"],
    "description": "releases an object and the resources owned by it; the pointer must not be used afterwards"
  },
  "buffer_copy": {
    "names": ["memcpy"],
    "description": "copies bytes from a source buffer into a destination buffer"
  },
  "init": {
    "names": ["xmlSAXVersion"],
    "description": "initializes an object or handler structure to a default state"
  },
  "parser_input": {
    "names": ["xmlCtxtReadMemory"],
    "description": "parses an in-memory document, typically taking a parser context and a character buffer"
  }
}
*/
