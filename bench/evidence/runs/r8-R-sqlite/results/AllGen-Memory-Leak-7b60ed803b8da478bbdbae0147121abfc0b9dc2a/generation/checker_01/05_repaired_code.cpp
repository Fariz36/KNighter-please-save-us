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
#include "llvm/ADT/DenseMap.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map tracking resources that are still owned by a local pointer.
// The value is always true if the region is present.
REGISTER_MAP_WITH_PROGRAMSTATE(OwnedRegions, const MemRegion *, bool)

namespace {

class SAGenTestChecker : public Checker<eval::Call,
                                       check::PostCall,
                                       check::PreCall,
                                       check::EndFunction,
                                       check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;
  mutable llvm::DenseMap<const FunctionDecl *, const VarDecl *> LocalPtrMap;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory Leak", "Memory Management")) {}

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;

private:
  void reportLeak(const VarDecl *VD, CheckerContext &C) const;
};

bool SAGenTestChecker::evalCall(const CallEvent &Call, CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "allocator"))
    return false;

  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return false;
  const CallExpr *CE = dyn_cast<CallExpr>(OriginExpr);
  if (!CE)
    return false;

  ProgramStateRef State = C.getState();
  SValBuilder &SVB = C.getSValBuilder();
  const LocationContext *LCtx = C.getLocationContext();
  unsigned Count = C.blockCount();
  SVal RetVal = SVB.getConjuredHeapSymbolVal(CE, LCtx, Count);
  State = State->BindExpr(CE, LCtx, RetVal);
  C.addTransition(State);
  return true;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "allocator"))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  const MemRegion *MR = RetVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  State = State->set<OwnedRegions>(MR, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  bool Changed = false;

  if (knighter::callIsRole(Call, "deallocator") ||
      knighter::callIsRole(Call, "ownership_transfer")) {
    for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
      SVal ArgVal = Call.getArgSVal(i);
      const MemRegion *MR = ArgVal.getAsRegion();
      if (!MR)
        continue;
      MR = MR->getBaseRegion();
      if (State->get<OwnedRegions>(MR)) {
        State = State->remove<OwnedRegions>(MR);
        Changed = true;
      }
    }
  }

  if (Changed) {
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const {
  const LocationContext *LC = C.getLocationContext();
  const Decl *D = LC->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD)
    return;

  auto It = LocalPtrMap.find(FD);
  if (It == LocalPtrMap.end())
    return;
  const VarDecl *VD = It->second;
  if (!VD)
    return;

  ProgramStateRef State = C.getState();
  SVal VarSVal = State->getSVal(State->getLValue(VD, LC));
  const MemRegion *MR = VarSVal.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();

  const bool *Owned = State->get<OwnedRegions>(MR);
  if (Owned && *Owned) {
    reportLeak(VD, C);
  }
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;
  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  class LocalPtrFinder : public RecursiveASTVisitor<LocalPtrFinder> {
  public:
    const VarDecl *Found = nullptr;
    bool VisitVarDecl(VarDecl *VD) {
      if (knighter::declIsRole(VD, "local_owning_pointer")) {
        Found = VD;
        return false;
      }
      return true;
    }
  };

  LocalPtrFinder Finder;
  Finder.TraverseStmt(Body);
  if (Finder.Found) {
    LocalPtrMap[FD] = Finder.Found;
  }
}

void SAGenTestChecker::reportLeak(const VarDecl *VD, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Memory leak: local owning pointer not freed or transferred on this path.",
      N);
  Report->addRange(VD->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects memory leaks of local owning pointers that are not freed or "
      "transferred on some paths",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {
    "names": ["sqlite3SrcListDup", "sqlite3SelectNew", "sqlite3SrcListAppendFromTerm"],
    "description": "Function that produces a new owning pointer to a resource; the returned resource must be transferred or freed."
  },
  "ownership_transfer": {
    "names": ["sqlite3SrcListAppendList"],
    "description": "Function that consumes an owning pointer and attaches it to a destination, transferring ownership."
  },
  "deallocator": {
    "names": ["sqlite3SrcListDelete"],
    "description": "Function that frees a resource owned by a pointer."
  },
  "local_owning_pointer": {
    "names": ["pFromDup"],
    "description": "Local variable that owns a resource and is responsible for either transferring it or freeing it."
  },
  "destination_pointer": {
    "names": ["pSrc"],
    "description": "Field/pointer that receives ownership of a resource when a transfer function is called."
  }
}
*/
