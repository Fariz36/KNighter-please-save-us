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
#include "llvm/ADT/APSInt.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UntrustedSizeMap, const MemRegion*, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(ReportedMap, const MemRegion*, bool)

namespace {

class SAGenTestChecker : public Checker<
  check::PostStmt<DeclStmt>,
  check::PreStmt<BinaryOperator>,
  check::Bind
> {
  mutable std::unique_ptr<BugType> BT;

  bool isLengthOfFunction(CheckerContext &C) const;
  bool isUntrustedSizeInit(const Expr *Init) const;
  llvm::APSInt getTypeMax(QualType QT, CheckerContext &C) const;

public:
  SAGenTestChecker() : BT(new BugType(this, "Integer Overflow in Length Calculation", "Integer Overflow")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
};

bool SAGenTestChecker::isLengthOfFunction(CheckerContext &C) const {
  const Decl *D = C.getCurrentAnalysisDeclContext()->getDecl();
  if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
    return knighter::declIsRole(FD, "length_of");
  }
  return false;
}

bool SAGenTestChecker::isUntrustedSizeInit(const Expr *Init) const {
  if (!Init)
    return false;
  Init = Init->IgnoreParenCasts();
  if (const auto *ME = dyn_cast<MemberExpr>(Init)) {
    const Expr *Base = ME->getBase()->IgnoreParenCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      return isa<ParmVarDecl>(DRE->getDecl());
    }
  } else if (const auto *DRE = dyn_cast<DeclRefExpr>(Init)) {
    return isa<ParmVarDecl>(DRE->getDecl());
  }
  return false;
}

llvm::APSInt SAGenTestChecker::getTypeMax(QualType QT, CheckerContext &C) const {
  ASTContext &AC = C.getASTContext();
  unsigned Width = AC.getIntWidth(QT);
  if (QT->isSignedIntegerType())
    return llvm::APSInt(llvm::APInt::getSignedMaxValue(Width), false);
  else
    return llvm::APSInt(llvm::APInt::getMaxValue(Width), true);
}

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS, CheckerContext &C) const {
  if (!isLengthOfFunction(C))
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (const Decl *D : DS->decls()) {
    const auto *VD = dyn_cast<VarDecl>(D);
    if (!VD || !VD->getType()->isIntegerType() || !VD->hasInit())
      continue;

    if (isUntrustedSizeInit(VD->getInit())) {
      SVal LVal = State->getLValue(VD, C.getLocationContext());
      const MemRegion *MR = LVal.getAsRegion();
      if (MR) {
        MR = MR->getBaseRegion();
        if (MR) {
          State = State->set<UntrustedSizeMap>(MR, true);
          Changed = true;
        }
      }
    }
  }

  if (Changed)
    C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const {
  if (!isLengthOfFunction(C))
    return;

  const auto *BO = dyn_cast<BinaryOperator>(S);
  if (!BO || !BO->isAssignmentOp())
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  if (State->get<UntrustedSizeMap>(MR)) {
    State = State->remove<UntrustedSizeMap>(MR);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const {
  if (!isLengthOfFunction(C))
    return;

  if (BO->isAssignmentOp())
    return;

  BinaryOperator::Opcode Op = BO->getOpcode();
  if (Op != BO_Add && Op != BO_Sub && Op != BO_Mul && Op != BO_Div)
    return;

  ProgramStateRef State = C.getState();
  bool Changed = false;

  for (const Expr *Operand : {BO->getLHS(), BO->getRHS()}) {
    const auto *DRE = dyn_cast<DeclRefExpr>(Operand->IgnoreParenCasts());
    if (!DRE)
      continue;

    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      continue;

    SVal LVal = State->getLValue(VD, C.getLocationContext());
    const MemRegion *MR = LVal.getAsRegion();
    if (!MR)
      continue;
    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    if (!State->get<UntrustedSizeMap>(MR))
      continue;

    if (State->get<ReportedMap>(MR))
      continue;

    SVal OpVal = State->getSVal(Operand, C.getLocationContext());
    SymbolRef Sym = OpVal.getAsSymbol();
    if (!Sym)
      continue;

    const llvm::APSInt *MaxVal = inferSymbolMaxVal(Sym, C);
    llvm::APSInt TypeMax = getTypeMax(VD->getType(), C);

    if (MaxVal == nullptr || *MaxVal >= TypeMax) {
      State = State->set<ReportedMap>(MR, true);
      ExplodedNode *N = C.generateNonFatalErrorNode(State);
      if (!N)
        continue;

      auto report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Unchecked arithmetic on untrusted size may overflow.", N);
      report->addRange(BO->getSourceRange());
      C.emitReport(std::move(report));

      Changed = true;
    }
  }

  if (Changed)
    C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in derived length calculations on untrusted size",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "length_of": {"names": ["encoder_base64_size"], "description": "computes a derived length from an input size; performs arithmetic on an untrusted input size and must validate it against a maximum safe bound before calculating"}
}
*/
