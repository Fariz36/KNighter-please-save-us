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
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/StringRef.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state to track symbols from narrow untrusted network reads
REGISTER_SET_WITH_PROGRAMSTATE(NarrowUntrustedSyms, SymbolRef)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Narrow integer used in size check",
                       "Integer Overflow")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  bool isNetworkReadFunction(const CallEvent &Call) const;
  bool isNarrowIntegerType(QualType QT, ASTContext &Ctx) const;
  bool containsNarrowUntrustedSymbol(const Expr *E, ProgramStateRef State,
                                     CheckerContext &C,
                                     SymbolRef &FoundSym) const;
  bool isSizeLike(const Expr *E, ASTContext &Ctx) const;
  bool hasArithmeticOp(const Expr *E) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isNetworkReadFunction(const CallEvent &Call) const {
  if (const IdentifierInfo *ID = Call.getCalleeIdentifier()) {
    StringRef Name = ID->getName();
    return Name == "Curl_read16_le" || Name == "Curl_read32_le" ||
           Name == "Curl_read64_le" || Name == "ntohs" || Name == "ntohl" ||
           Name == "get_unaligned_le16" || Name == "get_unaligned_le32" ||
           Name == "get_unaligned_le64";
  }
  return false;
}

bool SAGenTestChecker::isNarrowIntegerType(QualType QT, ASTContext &Ctx) const {
  if (!QT->isIntegerType())
    return false;
  unsigned TypeSize = Ctx.getTypeSize(QT);
  unsigned SizeTSize = Ctx.getTypeSize(Ctx.getSizeType());
  return TypeSize < SizeTSize;
}

bool SAGenTestChecker::containsNarrowUntrustedSymbol(
    const Expr *E, ProgramStateRef State, CheckerContext &C,
    SymbolRef &FoundSym) const {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    SVal V = State->getSVal(DRE, C.getLocationContext());
    if (SymbolRef Sym = V.getAsSymbol()) {
      if (State->contains<NarrowUntrustedSyms>(Sym)) {
        FoundSym = Sym;
        return true;
      }
    }
  } else if (const MemberExpr *ME = dyn_cast<MemberExpr>(E)) {
    SVal V = State->getSVal(ME, C.getLocationContext());
    if (SymbolRef Sym = V.getAsSymbol()) {
      if (State->contains<NarrowUntrustedSyms>(Sym)) {
        FoundSym = Sym;
        return true;
      }
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildExpr = dyn_cast<Expr>(Child)) {
      if (containsNarrowUntrustedSymbol(ChildExpr, State, C, FoundSym))
        return true;
    }
  }
  return false;
}

bool SAGenTestChecker::isSizeLike(const Expr *E, ASTContext &Ctx) const {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  // Integer literals are not size-like for our purposes.
  if (isa<IntegerLiteral>(E))
    return false;

  // DeclRefExpr, MemberExpr, and sizeof expressions are size-like.
  if (isa<DeclRefExpr>(E) || isa<MemberExpr>(E) ||
      isa<UnaryExprOrTypeTraitExpr>(E))
    return true;

  // Any expression whose type is at least as wide as size_t is size-like.
  QualType QT = E->getType();
  if (QT->isIntegerType()) {
    if (Ctx.getTypeSize(QT) >= Ctx.getTypeSize(Ctx.getSizeType()))
      return true;
  }
  return false;
}

bool SAGenTestChecker::hasArithmeticOp(const Expr *E) const {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_Add || Op == BO_Sub || Op == BO_Mul)
      return true;
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildExpr = dyn_cast<Expr>(Child)) {
      if (hasArithmeticOp(ChildExpr))
        return true;
    }
  }
  return false;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isNetworkReadFunction(Call))
    return;

  ProgramStateRef State = C.getState();
  const Expr *CE = Call.getOriginExpr();
  if (!CE)
    return;

  const BinaryOperator *BO =
      findSpecificTypeInParents<BinaryOperator>(CE, C);
  if (!BO || !BO->isAssignmentOp())
    return;

  const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
  QualType LHSType = LHS->getType();
  ASTContext &Ctx = C.getASTContext();
  if (!isNarrowIntegerType(LHSType, Ctx))
    return;

  SVal RetVal = Call.getReturnValue();
  if (SymbolRef Sym = RetVal.getAsSymbol()) {
    State = State->add<NarrowUntrustedSyms>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *Cond = dyn_cast<Expr>(Condition);
  if (!Cond)
    return;
  Cond = Cond->IgnoreParens();

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GT && Op != BO_GE && Op != BO_LT && Op != BO_LE)
    return;

  ProgramStateRef State = C.getState();
  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();

  SymbolRef NarrowSym = nullptr;
  bool LHSHasNarrow = containsNarrowUntrustedSymbol(LHS, State, C, NarrowSym);
  bool RHSHasNarrow = false;
  if (!LHSHasNarrow) {
    RHSHasNarrow = containsNarrowUntrustedSymbol(RHS, State, C, NarrowSym);
  }

  if (!LHSHasNarrow && !RHSHasNarrow)
    return;

  const Expr *NarrowSide = LHSHasNarrow ? LHS : RHS;
  const Expr *OtherSide = LHSHasNarrow ? RHS : LHS;

  if (!isSizeLike(OtherSide, C.getASTContext()))
    return;

  if (!hasArithmeticOp(NarrowSide))
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Narrow integer used in size check; may overflow/truncate. Use size_t "
      "for length/offset variables.",
      N);
  report->addRange(Cond->getSourceRange());
  C.emitReport(std::move(report));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects narrow integer variables from untrusted network reads used in "
      "size checks",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
