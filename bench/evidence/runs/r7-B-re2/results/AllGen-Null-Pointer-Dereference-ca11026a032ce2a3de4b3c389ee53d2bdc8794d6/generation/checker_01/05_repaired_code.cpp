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
#include "clang/AST/ExprCXX.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps
REGISTER_MAP_WITH_PROGRAMSTATE(WalkerStatusMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(WalkResultMap, SymbolRef, const MemRegion*)
REGISTER_MAP_WITH_PROGRAMSTATE(SimplifyNullMap, SymbolRef, bool)

namespace {

// Helper: Check if the call is Regexp::Simplify
static bool isRegexpSimplify(const CallEvent &Call) {
  const Decl *D = Call.getDecl();
  if (!D) return false;
  const auto *MD = dyn_cast<CXXMethodDecl>(D);
  if (!MD) return false;
  if (MD->getNameAsString() != "Simplify") return false;
  const CXXRecordDecl *Parent = MD->getParent();
  if (!Parent) return false;
  return Parent->getNameAsString() == "Regexp";
}

// Recursively mark checks in condition
static void markChecksInCondition(const Stmt *S, CheckerContext &C,
                                  ProgramStateRef &State) {
  if (!S) return;

  if (const auto *CE = dyn_cast<CXXMemberCallExpr>(S)) {
    if (ExprHasName(CE, "stopped_early", C)) {
      const Expr *ObjExpr = CE->getImplicitObjectArgument();
      if (ObjExpr) {
        SVal ObjVal = State->getSVal(ObjExpr, C.getLocationContext());
        if (const MemRegion *MR = ObjVal.getAsRegion()) {
          const MemRegion *Base = MR->getBaseRegion();
          if (State->get<WalkerStatusMap>(Base)) {
            State = State->set<WalkerStatusMap>(Base, true);
          }
        }
      }
    }
  } else if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    SymbolRef Sym = State->getSVal(DRE, C.getLocationContext()).getAsSymbol();
    if (Sym) {
      const bool *Checked = State->get<SimplifyNullMap>(Sym);
      if (Checked && *Checked == false) {
        State = State->set<SimplifyNullMap>(Sym, true);
      }
    }
  } else if (const auto *ME = dyn_cast<MemberExpr>(S)) {
    SymbolRef Sym = State->getSVal(ME, C.getLocationContext()).getAsSymbol();
    if (Sym) {
      const bool *Checked = State->get<SimplifyNullMap>(Sym);
      if (Checked && *Checked == false) {
        State = State->set<SimplifyNullMap>(Sym, true);
      }
    }
  }

  for (const Stmt *Child : S->children()) {
    markChecksInCondition(Child, C, State);
  }
}

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::PreCall,
                                        check::BranchCondition,
                                        check::PreStmt<ReturnStmt>> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "RE2 Regexp Simplify",
                       "Ignored early termination")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *RS, CheckerContext &C) const;

private:
  void reportBug(StringRef Msg, SourceRange Range, CheckerContext &C) const;
  void checkSymbolUse(SymbolRef Sym, const CallEvent &Call, CheckerContext &C,
                      ProgramStateRef State) const;
};

void SAGenTestChecker::reportBug(StringRef Msg, SourceRange Range,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N) return;

  auto report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
  report->addRange(Range);
  C.emitReport(std::move(report));
}

void SAGenTestChecker::checkSymbolUse(SymbolRef Sym, const CallEvent &Call,
                                      CheckerContext &C,
                                      ProgramStateRef State) const {
  // Check Walk result
  if (const MemRegion * const *WalkerMRPtr = State->get<WalkResultMap>(Sym)) {
    const MemRegion *WalkerMR = *WalkerMRPtr;
    const bool *Checked = State->get<WalkerStatusMap>(WalkerMR);
    if (Checked && *Checked == false) {
      reportBug("Walk result used before checking stopped_early()",
                Call.getSourceRange(), C);
    }
  }

  // Check Simplify result
  if (const bool *Checked = State->get<SimplifyNullMap>(Sym)) {
    if (*Checked == false) {
      reportBug("Simplify() result may be NULL and is used without check",
                Call.getSourceRange(), C);
    }
  }
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef Name = ID->getName();

    if (Name == "Walk" && isa<CXXMemberCall>(&Call)) {
      const auto *MC = cast<CXXMemberCall>(&Call);
      SVal ThisVal = MC->getCXXThisVal();
      const MemRegion *WalkerMR = ThisVal.getAsRegion();
      if (!WalkerMR) return;
      WalkerMR = WalkerMR->getBaseRegion();

      SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
      if (RetSym) {
        State = State->set<WalkerStatusMap>(WalkerMR, false);
        State = State->set<WalkResultMap>(RetSym, WalkerMR);
        C.addTransition(State);
      }
    } else if (Name == "Simplify" && isRegexpSimplify(Call)) {
      SymbolRef RetSym = Call.getReturnValue().getAsSymbol();
      if (RetSym) {
        State = State->set<SimplifyNullMap>(RetSym, false);
        C.addTransition(State);
      }
    }
  }
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Check explicit arguments
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    SVal ArgVal = Call.getArgSVal(i);
    SymbolRef Sym = ArgVal.getAsSymbol();
    if (Sym) {
      checkSymbolUse(Sym, Call, C, State);
    }
  }

  // Check implicit object for member calls
  if (const auto *MC = dyn_cast<CXXMemberCall>(&Call)) {
    SVal ThisVal = MC->getCXXThisVal();
    SymbolRef Sym = ThisVal.getAsSymbol();
    if (Sym) {
      checkSymbolUse(Sym, Call, C, State);
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  markChecksInCondition(Condition, C, State);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreStmt(const ReturnStmt *RS,
                                    CheckerContext &C) const {
  const Expr *RetE = RS->getRetValue();
  if (!RetE) return;

  ProgramStateRef State = C.getState();
  SVal RetVal = State->getSVal(RetE, C.getLocationContext());
  SymbolRef Sym = RetVal.getAsSymbol();
  if (!Sym) return;

  if (const MemRegion * const *WalkerMRPtr = State->get<WalkResultMap>(Sym)) {
    const MemRegion *WalkerMR = *WalkerMRPtr;
    const bool *Checked = State->get<WalkerStatusMap>(WalkerMR);
    if (Checked && *Checked == false) {
      reportBug("Returning Walk result without checking stopped_early()",
                RS->getSourceRange(), C);
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects ignored early termination in RE2 Walk/Simplify",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
