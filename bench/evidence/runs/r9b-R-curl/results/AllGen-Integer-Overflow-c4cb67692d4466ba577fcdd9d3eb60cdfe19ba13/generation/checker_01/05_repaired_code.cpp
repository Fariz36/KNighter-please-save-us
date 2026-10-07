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
#include "llvm/ADT/SmallPtrSet.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(NarrowUntrustedSizeMap, const MemRegion *, bool)

namespace {

struct ConditionInfo {
  bool HasComparison = false;
  bool HasAdditive = false;
  bool HasTrackedInAdditive = false;
  llvm::SmallPtrSet<const MemRegion *, 8> TrackedRegions;
};

static bool containsTrackedDeclRef(const Stmt *S, CheckerContext &C,
                                   ProgramStateRef State) {
  if (!S)
    return false;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    const MemRegion *MR = getMemRegionFromExpr(DRE, C);
    if (MR) {
      MR = MR->getBaseRegion();
      if (State->get<NarrowUntrustedSizeMap>(MR))
        return true;
    }
  }

  for (Stmt::const_child_iterator I = S->child_begin(), E = S->child_end();
       I != E; ++I) {
    if (containsTrackedDeclRef(*I, C, State))
      return true;
  }
  return false;
}

static void analyzeCondition(const Stmt *S, CheckerContext &C,
                             ProgramStateRef State, ConditionInfo &Info) {
  if (!S)
    return;

  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isComparisonOp())
      Info.HasComparison = true;
    if (BO->getOpcode() == BO_Add || BO->getOpcode() == BO_Sub) {
      Info.HasAdditive = true;
      if (containsTrackedDeclRef(BO, C, State))
        Info.HasTrackedInAdditive = true;
    }
  }

  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    const MemRegion *MR = getMemRegionFromExpr(DRE, C);
    if (MR) {
      MR = MR->getBaseRegion();
      if (State->get<NarrowUntrustedSizeMap>(MR))
        Info.TrackedRegions.insert(MR);
    }
  }

  for (Stmt::const_child_iterator I = S->child_begin(), E = S->child_end();
       I != E; ++I) {
    analyzeCondition(*I, C, State, Info);
  }
}

static void collectDeclRefs(const Stmt *S,
                            llvm::SmallVectorImpl<const DeclRefExpr *> &Refs) {
  if (!S)
    return;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(S))
    Refs.push_back(DRE);

  for (Stmt::const_child_iterator I = S->child_begin(), E = S->child_end();
       I != E; ++I) {
    collectDeclRefs(*I, Refs);
  }
}

class SAGenTestChecker
    : public Checker<check::Bind, check::BranchCondition, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Narrow untrusted size bypasses bounds check",
                       "Integer Overflow")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;
  R = R->getBaseRegion();

  const VarRegion *VR = dyn_cast<VarRegion>(R);
  if (!VR)
    return;

  const VarDecl *VD = VR->getDecl();
  if (!VD)
    return;

  ASTContext &ASTCtx = C.getASTContext();
  QualType QT = VD->getType();
  if (!QT->isIntegerType())
    return;

  unsigned Width = ASTCtx.getTypeSize(QT);
  unsigned SizeWidth = ASTCtx.getTypeSize(ASTCtx.getSizeType());
  if (Width >= SizeWidth)
    return;

  const Expr *RHS = nullptr;
  if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    for (const Decl *D : DS->decls()) {
      const auto *InitVD = dyn_cast<VarDecl>(D);
      if (InitVD && InitVD == VD) {
        RHS = InitVD->getInit();
        break;
      }
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign)
      RHS = BO->getRHS();
  }

  if (!RHS)
    return;

  RHS = RHS->IgnoreParenCasts();
  if (const auto *CE = dyn_cast<CallExpr>(RHS)) {
    if (knighter::callExprIsRole(CE, "parser_input", ASTCtx)) {
      State = State->set<NarrowUntrustedSizeMap>(R, false);
    } else {
      State = State->remove<NarrowUntrustedSizeMap>(R);
    }
  } else {
    State = State->remove<NarrowUntrustedSizeMap>(R);
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  ProgramStateRef State = C.getState();
  ConditionInfo Info;
  analyzeCondition(Condition, C, State, Info);

  if (!Info.HasComparison || !Info.HasAdditive || !Info.HasTrackedInAdditive)
    return;

  for (const MemRegion *MR : Info.TrackedRegions) {
    State = State->set<NarrowUntrustedSizeMap>(MR, true);
  }

  if (State != C.getState())
    C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "buffer_copy"))
    return;

  const Expr *Origin = Call.getOriginExpr();
  if (!Origin)
    return;
  const auto *CE = dyn_cast<CallExpr>(Origin);
  if (!CE)
    return;

  ProgramStateRef State = C.getState();
  bool ShouldReport = false;

  for (unsigned I = 0, E = CE->getNumArgs(); I != E; ++I) {
    const Expr *Arg = CE->getArg(I);
    llvm::SmallVector<const DeclRefExpr *, 8> Refs;
    collectDeclRefs(Arg, Refs);

    for (const DeclRefExpr *DRE : Refs) {
      const MemRegion *MR = getMemRegionFromExpr(DRE, C);
      if (!MR)
        continue;
      MR = MR->getBaseRegion();
      const bool *Tracked = State->get<NarrowUntrustedSizeMap>(MR);
      if (Tracked && *Tracked) {
        ShouldReport = true;
        break;
      }
    }
    if (ShouldReport)
      break;
  }

  if (!ShouldReport)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Untrusted size bypasses bounds check before buffer copy", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects narrow untrusted size/offset values that bypass an arithmetic "
      "bounds check before a buffer copy",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["Curl_read16_le"], "description": "reads an untrusted size or offset value from parser/network input"},
  "buffer_copy": {"names": ["Curl_client_write"], "description": "copies a buffer of a given size to an output or sink"}
}
*/
