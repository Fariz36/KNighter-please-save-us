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
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(AnchoredRegionMap, const MemRegion *, bool)

namespace {

static bool isWeakObjectType(QualType QT) {
  if (!QT->isPointerType())
    return false;

  QualType Pointee =
      QT->getPointeeType().getUnqualifiedType().getCanonicalType();
  const RecordType *RT = Pointee->getAs<RecordType>();
  if (!RT)
    return false;

  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return false;

  return knighter::declIsRole(RD, "weakly_referenced_object");
}

static void getGCArgRegions(const CallEvent &Call, CheckerContext &C,
                            llvm::SmallVectorImpl<const MemRegion *> &Regions) {
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;

    QualType ArgTy = ArgE->getType();
    if (!isWeakObjectType(ArgTy))
      continue;

    const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
    if (!MR)
      continue;

    MR = MR->getBaseRegion();
    if (MR)
      Regions.push_back(MR);
  }
}

class SAGenTestChecker : public Checker<check::PreCall, check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Weak GC Object Use Without Root Anchor",
                       "Garbage Collector Lifetime")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (knighter::callIsRole(Call, "root_anchor")) {
    llvm::SmallVector<const MemRegion *, 4> Regions;
    getGCArgRegions(Call, C, Regions);
    for (const MemRegion *MR : Regions) {
      State = State->set<AnchoredRegionMap>(MR, true);
    }
    C.addTransition(State);
    return;
  }

  if (knighter::callIsRole(Call, "gc_triggering_operation")) {
    llvm::SmallVector<const MemRegion *, 4> Regions;
    getGCArgRegions(Call, C, Regions);

    bool MissingAnchor = false;
    for (const MemRegion *MR : Regions) {
      const bool *Anchored = State->get<AnchoredRegionMap>(MR);
      if (!Anchored || !*Anchored) {
        MissingAnchor = true;
        break;
      }
    }

    if (MissingAnchor) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (N) {
        auto report = std::make_unique<PathSensitiveBugReport>(
            *BT,
            "Weak GC object used without a root anchor before GC-triggering call.",
            N);
        report->addRange(Call.getSourceRange());
        C.emitReport(std::move(report));
      }
    }
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "gc_triggering_operation"))
    return;

  ProgramStateRef State = C.getState();
  llvm::SmallVector<const MemRegion *, 4> Regions;
  getGCArgRegions(Call, C, Regions);
  for (const MemRegion *MR : Regions) {
    State = State->remove<AnchoredRegionMap>(MR);
  }
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects use of weakly referenced GC objects without a root anchor before a GC-triggering call",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "gc_triggering_operation": {
    "names": ["luaH_finishset"],
    "description": "operation that may allocate/rehash and trigger an emergency GC while using a GC-managed object"
  },
  "root_anchor": {
    "names": ["sethvalue2s"],
    "description": "anchors a GC-managed object in a strong root (e.g., on the Lua stack) so it cannot be collected during a GC-triggering operation"
  },
  "weakly_referenced_object": {
    "names": ["Table"],
    "description": "type of GC-managed object that can be reachable only through a weak container and may be collected during an emergency GC"
  }
}
*/
