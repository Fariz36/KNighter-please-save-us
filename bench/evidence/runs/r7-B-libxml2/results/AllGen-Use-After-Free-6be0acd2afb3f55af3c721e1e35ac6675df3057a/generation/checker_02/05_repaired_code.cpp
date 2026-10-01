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
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track whether a node (by memory region) is currently linked into a tree.
REGISTER_MAP_WITH_PROGRAMSTATE(LinkedNodes, const MemRegion *, bool)
// Fallback for symbolic pointers (top-level function parameters).
REGISTER_MAP_WITH_PROGRAMSTATE(LinkedNodeSyms, SymbolRef, bool)

namespace {
class SAGenTestChecker
    : public Checker<check::BeginFunction, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Freeing linked node", "Memory Management")) {}

  void checkBeginFunction(CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C) const;
  bool isLinkingFunction(StringRef Name,
                         llvm::SmallVectorImpl<unsigned> &Params) const;
};

void SAGenTestChecker::checkBeginFunction(CheckerContext &C) const {
  const LocationContext *LCtx = C.getLocationContext();
  const Decl *D = LCtx->getDecl();
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  llvm::SmallVector<unsigned, 4> Params;
  if (!isLinkingFunction(FD->getName(), Params))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned Idx : Params) {
    if (Idx >= FD->getNumParams())
      continue;
    const ParmVarDecl *PVD = FD->getParamDecl(Idx);
    SVal V = State->getSVal(State->getLValue(PVD, LCtx));
    if (const MemRegion *MR = V.getAsRegion()) {
      MR = MR->getBaseRegion();
      State = State->set<LinkedNodes>(MR, true);
    } else if (SymbolRef Sym = V.getAsSymbol()) {
      State = State->set<LinkedNodeSyms>(Sym, true);
    }
  }
  C.addTransition(State);
}

bool SAGenTestChecker::isLinkingFunction(
    StringRef Name, llvm::SmallVectorImpl<unsigned> &Params) const {
  if (Name == "xmlAddChild" || Name == "xmlAddSibling" ||
      Name == "xmlAddNextSibling" || Name == "xmlAddPrevSibling" ||
      Name == "xmlReplaceNode") {
    // The node being linked is the second parameter (index 1).
    Params.push_back(1);
    return true;
  }
  return false;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  const Expr *E = Call.getOriginExpr();
  if (!E)
    return;

  ProgramStateRef State = C.getState();

  // Handle unlinking.
  if (ExprHasName(E, "xmlUnlinkNodeInternal", C) ||
      ExprHasName(E, "xmlUnlinkNode", C)) {
    if (Call.getNumArgs() < 1)
      return;
    SVal Arg0 = Call.getArgSVal(0);
    if (const MemRegion *MR = Arg0.getAsRegion()) {
      MR = MR->getBaseRegion();
      if (State->get<LinkedNodes>(MR)) {
        State = State->set<LinkedNodes>(MR, false);
        C.addTransition(State);
      }
    } else if (SymbolRef Sym = Arg0.getAsSymbol()) {
      if (State->get<LinkedNodeSyms>(Sym)) {
        State = State->set<LinkedNodeSyms>(Sym, false);
        C.addTransition(State);
      }
    }
    return;
  }

  // Handle freeing.
  if (ExprHasName(E, "xmlFreeNode", C)) {
    if (Call.getNumArgs() < 1)
      return;
    SVal Arg0 = Call.getArgSVal(0);
    bool IsLinked = false;

    if (const MemRegion *MR = Arg0.getAsRegion()) {
      MR = MR->getBaseRegion();
      const bool *Linked = State->get<LinkedNodes>(MR);
      if (Linked && *Linked)
        IsLinked = true;
    } else if (SymbolRef Sym = Arg0.getAsSymbol()) {
      const bool *Linked = State->get<LinkedNodeSyms>(Sym);
      if (Linked && *Linked)
        IsLinked = true;
    }

    if (IsLinked)
      reportBug(Call, C);
  }
}

void SAGenTestChecker::reportBug(const CallEvent &Call,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Freeing linked node without xmlUnlinkNodeInternal", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects freeing linked nodes without unlinking them first",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
