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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(GitStrOwnedMap, const MemRegion *, bool)

namespace {

static bool isCallNamed(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *Origin = Call.getOriginExpr();
  return Origin && ExprHasName(Origin, Name, C);
}

static bool isAllocator(const CallEvent &Call, CheckerContext &C) {
  return isCallNamed(Call, "git_fs_path_prettify_dir", C) ||
         isCallNamed(Call, "git_str_printf", C) ||
         isCallNamed(Call, "git_str_puts", C) ||
         isCallNamed(Call, "git_str_join", C) ||
         isCallNamed(Call, "git_str_join_n", C) ||
         isCallNamed(Call, "git_str_joinpath", C) ||
         isCallNamed(Call, "git_str_put", C) ||
         isCallNamed(Call, "git_str_putc", C) ||
         isCallNamed(Call, "git_str_vprintf", C) ||
         isCallNamed(Call, "git_str_set", C);
}

static bool isCleanup(const CallEvent &Call, CheckerContext &C) {
  return isCallNamed(Call, "git_str_dispose", C) ||
         isCallNamed(Call, "git_str_detach", C) ||
         isCallNamed(Call, "git_str_clear", C);
}

static const MemRegion *getGitStrRegionFromArg(const Expr *Arg, CheckerContext &C) {
  if (!Arg)
    return nullptr;

  const Expr *E = Arg->IgnoreParenImpCasts();
  const UnaryOperator *UO = dyn_cast<UnaryOperator>(E);
  if (!UO || UO->getOpcode() != UO_AddrOf)
    return nullptr;

  const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub);
  if (!DRE)
    return nullptr;

  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return nullptr;

  QualType QT = VD->getType().getUnqualifiedType();
  if (QT.getAsString() != "git_str")
    return nullptr;

  const MemRegion *MR = getMemRegionFromExpr(DRE, C);
  if (!MR)
    return nullptr;

  return MR->getBaseRegion();
}

class SAGenTestChecker : public Checker<check::PostCall, check::PreStmt<ReturnStmt>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "GitStrLeak", "Memory leak")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  bool Changed = false;

  if (isAllocator(Call, C)) {
    for (unsigned I = 0, E = Call.getNumArgs(); I < E; ++I) {
      const Expr *Arg = Call.getArgExpr(I);
      if (const MemRegion *MR = getGitStrRegionFromArg(Arg, C)) {
        State = State->set<GitStrOwnedMap>(MR, true);
        Changed = true;
      }
    }
  } else if (isCleanup(Call, C)) {
    if (Call.getNumArgs() > 0) {
      const Expr *Arg = Call.getArgExpr(0);
      if (const MemRegion *MR = getGitStrRegionFromArg(Arg, C)) {
        State = State->remove<GitStrOwnedMap>(MR);
        Changed = true;
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const {
  // Do not report if the function returns ownership of a git_str.
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  if (FD) {
    QualType RT = FD->getReturnType();
    if (RT->isRecordType() || RT->isPointerType())
      return;
  }

  ProgramStateRef State = C.getState();
  const auto &Map = State->get<GitStrOwnedMap>();
  bool Owned = false;
  for (auto I = Map.begin(), E = Map.end(); I != E; ++I) {
    if (I->second) {
      Owned = true;
      break;
    }
  }

  if (!Owned)
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing git_str_dispose before return", N);
  report->addRange(RS->getSourceRange());
  C.emitReport(std::move(report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing git_str_dispose before return (git_str leak)",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
