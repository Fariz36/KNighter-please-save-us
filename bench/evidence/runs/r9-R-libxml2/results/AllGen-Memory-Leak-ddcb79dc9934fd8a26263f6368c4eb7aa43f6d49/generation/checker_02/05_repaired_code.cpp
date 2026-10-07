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
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "llvm/ADT/DenseSet.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(AllocMap, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(CopiedAllocMap, const MemRegion *, bool)

namespace {

class OwnedFieldCollector : public RecursiveASTVisitor<OwnedFieldCollector> {
  const FunctionDecl *CleanupFD;
  llvm::DenseSet<const FieldDecl *> &OwnedFields;

public:
  OwnedFieldCollector(const FunctionDecl *FD,
                      llvm::DenseSet<const FieldDecl *> &Set)
      : CleanupFD(FD), OwnedFields(Set) {}

  bool VisitCallExpr(CallExpr *CE) {
    const FunctionDecl *Callee = CE->getDirectCallee();
    if (!Callee || !knighter::declIsRole(Callee, "deallocator"))
      return true;

    for (unsigned I = 0, E = CE->getNumArgs(); I < E; ++I) {
      const Expr *Arg = CE->getArg(I)->IgnoreParenImpCasts();
      const MemberExpr *ME = dyn_cast<MemberExpr>(Arg);
      if (!ME)
        continue;
      if (!isFromCleanupParam(ME))
        continue;
      if (const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl()))
        OwnedFields.insert(FD);
    }
    return true;
  }

private:
  bool isFromCleanupParam(const MemberExpr *ME) const {
    const Expr *Base = ME->getBase()->IgnoreParenImpCasts();

    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base)) {
      const ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl());
      if (!PVD)
        return false;
      const FunctionDecl *Owner =
          dyn_cast<FunctionDecl>(PVD->getDeclContext());
      return Owner == CleanupFD;
    }

    if (const MemberExpr *BaseME = dyn_cast<MemberExpr>(Base))
      return isFromCleanupParam(BaseME);

    return false;
  }
};

} // end anonymous namespace

namespace {

class SAGenTestChecker
    : public Checker<eval::Call, check::PostCall, check::Bind,
                     check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;
  mutable llvm::DenseSet<const FieldDecl *> OwnedFields;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Memory Leak", "Memory Management")) {}

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

private:
  void reportLeak(const Stmt *S, CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::evalCall(const CallEvent &Call,
                                CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "allocator"))
    return false;

  const Expr *CE = Call.getOriginExpr();
  if (!CE)
    return false;

  SValBuilder &SVB = C.getSValBuilder();
  const LocationContext *LCtx = C.getLocationContext();
  SVal RetVal = SVB.getConjuredHeapSymbolVal(CE, LCtx, C.blockCount());
  if (!RetVal.getAs<Loc>())
    return false;

  ProgramStateRef State = C.getState();
  State = State->BindExpr(CE, LCtx, RetVal);
  C.addTransition(State);
  return true;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (knighter::callIsRole(Call, "allocator")) {
    const MemRegion *MR = Call.getReturnValue().getAsRegion();
    if (!MR)
      return;
    MR = MR->getBaseRegion();
    State = State->set<AllocMap>(MR, true);
    C.addTransition(State);
    return;
  }

  if (knighter::callIsRole(Call, "buffer_copy")) {
    if (Call.getNumArgs() < 1)
      return;

    const Expr *Dst = Call.getArgExpr(0);
    if (!Dst)
      return;

    const MemRegion *MR = getMemRegionFromExpr(Dst, C);
    if (!MR)
      return;
    MR = MR->getBaseRegion();

    if (State->get<AllocMap>(MR)) {
      State = State->set<CopiedAllocMap>(MR, true);
      C.addTransition(State);
    }
    return;
  }
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  const MemRegion *LocMR = Loc.getAsRegion();
  if (!LocMR)
    return;

  const FieldRegion *FR = dyn_cast<FieldRegion>(LocMR);
  if (!FR)
    return;

  const FieldDecl *FD = FR->getDecl();
  if (!FD || OwnedFields.count(FD) == 0)
    return;

  const MemRegion *ValMR = Val.getAsRegion();
  if (!ValMR)
    return;
  ValMR = ValMR->getBaseRegion();

  ProgramStateRef State = C.getState();
  if (!State->get<CopiedAllocMap>(ValMR))
    return;

  reportLeak(S, C);
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !knighter::declIsRole(FD, "cleanup"))
    return;

  if (const Stmt *Body = FD->getBody()) {
    OwnedFieldCollector Collector(FD, OwnedFields);
    Collector.TraverseStmt(const_cast<Stmt *>(Body));
  }
}

void SAGenTestChecker::reportLeak(const Stmt *S, CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential memory leak: overwriting owned field with newly allocated "
      "copy without freeing old value",
      N);

  if (S)
    Report->addRange(S->getSourceRange());

  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects overwriting owned fields with newly allocated copies without "
      "freeing the old value",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "allocator": {"names": ["xmlMalloc"], "description": "allocates memory; the returned pointer is owned by the caller"},
  "buffer_copy": {"names": ["memcpy"], "description": "copies bytes from a source into a destination buffer"},
  "deallocator": {"names": ["xmlFree"], "description": "frees a previously allocated memory object; the pointer must not be used afterwards"},
  "cleanup": {"names": ["xmlFreeParserCtxt"], "description": "frees an object and the resources owned by it; used to discover owned fields"}
}
*/
