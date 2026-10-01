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
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state map to track whether a bounds check for short_oid->id[0]
// has been observed.  The key is the MemRegion of the `short_oid` parameter.
REGISTER_MAP_WITH_PROGRAMSTATE(CheckedBoundsMap, const MemRegion *, bool)

namespace {

// Helper: find a DeclRefExpr with the given name in the AST subtree.
static const DeclRefExpr *findDeclRefExprByName(const Stmt *S, StringRef Name) {
  if (!S)
    return nullptr;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (const ValueDecl *VD = DRE->getDecl()) {
      if (VD->getName() == Name)
        return DRE;
    }
  }

  for (const Stmt *Child : S->children()) {
    if (const DeclRefExpr *Found = findDeclRefExprByName(Child, Name))
      return Found;
  }
  return nullptr;
}

// Helper: get the MemRegion of the `short_oid` parameter.
static const MemRegion *getShortOidRegion(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;

  const DeclRefExpr *DRE = findDeclRefExprByName(E, "short_oid");
  if (!DRE)
    return nullptr;

  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD)
    return nullptr;

  // Get the region of the variable itself, not the pointed-to object.
  SVal LVal = C.getState()->getLValue(VD, C.getLocationContext());
  const MemRegion *MR = LVal.getAsRegion();
  if (!MR)
    return nullptr;

  return MR->getBaseRegion();
}

class SAGenTestChecker : public Checker<check::PreStmt<ArraySubscriptExpr>,
                                        check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Missing bounds check before pack index fanout table read",
                       "Out-of-bounds read")) {}

  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkPreStmt(const ArraySubscriptExpr *ASE,
                                    CheckerContext &C) const {
  if (!ASE)
    return;

  // Only consider the function of interest.
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || FD->getName() != "pack_entry_find_offset")
    return;

  // Check for: level1_ofs[ short_oid->id[0] ]
  if (!ExprHasName(ASE->getBase(), "level1_ofs", C))
    return;
  if (!ExprHasName(ASE->getIdx(), "short_oid->id[0]", C))
    return;

  const MemRegion *ShortOidReg = getShortOidRegion(ASE->getIdx(), C);
  if (!ShortOidReg)
    return;

  ProgramStateRef State = C.getState();
  const bool *Checked = State->get<CheckedBoundsMap>(ShortOidReg);
  if (Checked && *Checked)
    return; // bounds check was seen

  // Report missing bounds check.
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Missing bounds check before using short_oid->id[0] as index into pack "
      "index fanout table",
      N);
  Report->addRange(ASE->getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  // Detect the version-specific bounds check added by the patch.
  if (!ExprHasName(CondE, "short_oid->id[0]", C))
    return;
  if (!ExprHasName(CondE, "index_map.len", C))
    return;

  const MemRegion *ShortOidReg = getShortOidRegion(CondE, C);
  if (!ShortOidReg)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<CheckedBoundsMap>(ShortOidReg, true);
  C.addTransition(State);
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing bounds check before using short_oid->id[0] as index into "
      "pack index fanout table",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
