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
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(UntrustedSizeSet, SymbolRef)

namespace {

class SAGenTestChecker : public Checker<check::PostCall, check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow in Size Check",
                       "Integer Overflow")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  void flattenAdd(const Expr *E,
                  llvm::SmallVectorImpl<const Expr *> &Ops) const;
  bool isNarrowIntegerType(QualType Ty, ASTContext &AC) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "untrusted_size"))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = RetVal.getAsSymbol();
  if (!Sym)
    return;

  State = State->add<UntrustedSizeSet>(Sym);
  C.addTransition(State);
}

void SAGenTestChecker::flattenAdd(
    const Expr *E, llvm::SmallVectorImpl<const Expr *> &Ops) const {
  if (!E)
    return;
  E = E->IgnoreParenImpCasts();
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Add) {
      flattenAdd(BO->getLHS(), Ops);
      flattenAdd(BO->getRHS(), Ops);
      return;
    }
  }
  Ops.push_back(E);
}

bool SAGenTestChecker::isNarrowIntegerType(QualType Ty, ASTContext &AC) const {
  if (!Ty->isIntegerType())
    return false;
  uint64_t TypeBits = AC.getTypeSize(Ty);
  uint64_t SizeTBits = AC.getTypeSize(AC.getSizeType());
  return TypeBits < SizeTBits;
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  if (!Condition)
    return;

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  // Strip parentheses and logical NOT.
  CondE = CondE->IgnoreParenImpCasts();
  while (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      CondE = UO->getSubExpr()->IgnoreParenImpCasts();
    } else {
      break;
    }
  }

  const BinaryOperator *BO = dyn_cast<BinaryOperator>(CondE);
  if (!BO)
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_GT && Op != BO_GE && Op != BO_LT && Op != BO_LE)
    return;

  // Determine which side of the relational operator is an addition.
  const Expr *AddSide = nullptr;
  const Expr *OtherSide = nullptr;

  if (const BinaryOperator *LHSBO =
          dyn_cast<BinaryOperator>(BO->getLHS()->IgnoreParenImpCasts())) {
    if (LHSBO->getOpcode() == BO_Add) {
      AddSide = BO->getLHS();
      OtherSide = BO->getRHS();
    }
  }

  if (!AddSide) {
    if (const BinaryOperator *RHSBO =
            dyn_cast<BinaryOperator>(BO->getRHS()->IgnoreParenImpCasts())) {
      if (RHSBO->getOpcode() == BO_Add) {
        AddSide = BO->getRHS();
        OtherSide = BO->getLHS();
      }
    }
  }

  if (!AddSide)
    return;

  llvm::SmallVector<const Expr *, 8> Ops;
  flattenAdd(AddSide, Ops);

  ProgramStateRef State = C.getState();
  bool hasUntrusted = false;
  bool hasNarrowUntrusted = false;
  bool hasConstant = false;

  ASTContext &AC = C.getASTContext();

  for (const Expr *OpExpr : Ops) {
    if (!OpExpr)
      continue;

    // Check if the operand's value is an untrusted symbol.
    SVal OpVal = State->getSVal(OpExpr, C.getLocationContext());
    if (SymbolRef Sym = OpVal.getAsSymbol()) {
      if (State->contains<UntrustedSizeSet>(Sym)) {
        hasUntrusted = true;
      }
    }

    // Check if the operand is a narrow integer variable.
    const Expr *E = OpExpr->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (isNarrowIntegerType(VD->getType(), AC)) {
          hasNarrowUntrusted = true;
        }
      }
    }

    // Check if the operand evaluates to a constant.
    llvm::APSInt ConstVal;
    if (EvaluateExprToInt(ConstVal, OpExpr, C)) {
      hasConstant = true;
    }
  }

  if (hasUntrusted && hasNarrowUntrusted && hasConstant) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Potential integer overflow in size check: untrusted 16-bit size "
        "used with narrow type; use size_t for arithmetic.",
        N);
    report->addRange(Condition->getSourceRange());
    C.emitReport(std::move(report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potential integer overflow in size checks involving untrusted "
      "sizes and narrow types",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "untrusted_size": {"names": ["Curl_read16_le"], "description": "reads a size or offset value from untrusted input"}
}
*/
