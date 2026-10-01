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
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/Support/Casting.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Map the symbolic return value of xmlNewIOInputStream to the MemRegion of
// its second argument (the input buffer).
REGISTER_MAP_WITH_PROGRAMSTATE(ReturnArgMap, SymbolRef, const MemRegion*)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Double Free", "Memory Management")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportDoubleFree(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

static bool isCallTo(const CallEvent &Call, StringRef Name, CheckerContext &C) {
  const Expr *E = Call.getOriginExpr();
  return E && ExprHasName(E, Name, C);
}

static bool isInThenBranch(const IfStmt *IS, const Stmt *S, CheckerContext &C) {
  if (!IS || !S)
    return false;

  const Stmt *Then = IS->getThen();
  if (!Then)
    return false;

  SourceRange ThenRange = Then->getSourceRange();
  SourceRange SRange = S->getSourceRange();
  if (!ThenRange.isValid() || !SRange.isValid())
    return false;

  const SourceManager &SM = C.getSourceManager();
  SourceLocation ThenBegin = ThenRange.getBegin();
  SourceLocation ThenEnd = ThenRange.getEnd();
  SourceLocation SBegin = SRange.getBegin();
  SourceLocation SEnd = SRange.getEnd();

  // Check if ThenBegin <= SBegin and SEnd <= ThenEnd
  bool beginOK = !SM.isBeforeInTranslationUnit(SBegin, ThenBegin);
  bool endOK = !SM.isBeforeInTranslationUnit(ThenEnd, SEnd);
  return beginOK && endOK;
}

static const Expr *getNullCheckPointerExpr(const Expr *Cond, ASTContext &ACtx) {
  if (!Cond)
    return nullptr;

  Cond = Cond->IgnoreParenImpCasts();

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      return UO->getSubExpr()->IgnoreParenImpCasts();
    }
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LHSIsNull = LHS->isNullPointerConstant(
          ACtx, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          ACtx, Expr::NPC_ValueDependentIsNull);
      if (LHSIsNull && !RHSIsNull)
        return RHS;
      if (RHSIsNull && !LHSIsNull)
        return LHS;
    }
  }

  return nullptr;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isCallTo(Call, "xmlNewIOInputStream", C))
    return;

  if (Call.getNumArgs() < 2)
    return;

  SVal RetVal = Call.getReturnValue();
  SymbolRef RetSym = RetVal.getAsSymbol();
  if (!RetSym)
    return;

  SVal InputVal = Call.getArgSVal(1);
  const MemRegion *InputReg = InputVal.getAsRegion();
  if (!InputReg)
    return;
  InputReg = InputReg->getBaseRegion();
  if (!InputReg)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<ReturnArgMap>(RetSym, InputReg);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!isCallTo(Call, "xmlFreeParserInputBuffer", C))
    return;

  if (Call.getNumArgs() < 1)
    return;

  const Expr *CE = Call.getOriginExpr();
  if (!CE)
    return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(CE, C);
  if (!IS)
    return;

  if (!isInThenBranch(IS, CE, C))
    return;

  ASTContext &ACtx = C.getASTContext();
  const Expr *PtrExpr = getNullCheckPointerExpr(IS->getCond(), ACtx);
  if (!PtrExpr)
    return;

  ProgramStateRef State = C.getState();
  SVal PtrVal = State->getSVal(PtrExpr, C.getLocationContext());
  SymbolRef RetSym = PtrVal.getAsSymbol();
  if (!RetSym)
    return;

  const MemRegion * const *InputRegPtr = State->get<ReturnArgMap>(RetSym);
  if (!InputRegPtr)
    return;
  const MemRegion *InputReg = *InputRegPtr;
  if (!InputReg)
    return;
  InputReg = InputReg->getBaseRegion();

  SVal FreeArg = Call.getArgSVal(0);
  const MemRegion *FreeReg = FreeArg.getAsRegion();
  if (!FreeReg)
    return;
  FreeReg = FreeReg->getBaseRegion();

  if (FreeReg != InputReg)
    return;

  reportDoubleFree(Call, C);
}

void SAGenTestChecker::reportDoubleFree(const CallEvent &Call,
                                        CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Double free: input already freed by xmlNewIOInputStream on failure", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects double free of input freed by xmlNewIOInputStream on failure",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
