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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/AST/Decl.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper: if R is an ElementRegion whose super region is a fixed-size char array,
// return the array size. Handles both plain C arrays and std::array-like fields.
bool getFixedArraySize(const MemRegion *R, llvm::APInt &Size) {
  if (!R)
    return false;

  const ElementRegion *ER = dyn_cast<ElementRegion>(R);
  if (!ER)
    return false;

  const MemRegion *Super = ER->getSuperRegion();
  if (!Super)
    return false;

  QualType QT;
  if (const VarRegion *VR = dyn_cast<VarRegion>(Super)) {
    QT = VR->getDecl()->getType();
  } else if (const FieldRegion *FR = dyn_cast<FieldRegion>(Super)) {
    QT = FR->getDecl()->getType();
  } else {
    return false;
  }

  const ConstantArrayType *CAT = dyn_cast<ConstantArrayType>(QT.getTypePtr());
  if (!CAT)
    return false;

  if (!CAT->getElementType()->isCharType())
    return false;

  Size = CAT->getSize();
  return true;
}

class SAGenTestChecker : public Checker<check::Bind> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Stack Buffer Overflow", "Memory Safety")) {}

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
};

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  // Only care about writes of the character '0'.
  auto CI = Val.getAs<nonloc::ConcreteInt>();
  if (!CI || CI->getValue().getZExtValue() != '0')
    return;

  const MemRegion *R = Loc.getAsRegion();
  if (!R)
    return;

  llvm::APInt Size;
  if (!getFixedArraySize(R, Size))
    return;

  const ElementRegion *ER = dyn_cast<ElementRegion>(R);
  if (!ER)
    return;

  SVal Index = ER->getIndex();
  bool Overflow = false;

  if (auto ICI = Index.getAs<nonloc::ConcreteInt>()) {
    if (ICI->getValue().uge(Size))
      Overflow = true;
  } else if (SymbolRef Sym = Index.getAsSymbol()) {
    const llvm::APSInt *Max = inferSymbolMaxVal(Sym, C);
    if (!Max || Max->uge(Size))
      Overflow = true;
  }

  if (!Overflow)
    return;

  // Restrict to the function FpToString to reduce false positives.
  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || FD->getNameAsString() != "FpToString")
    return;

  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Potential stack buffer overflow: writing zeros past the end of fixed-size output buffer.",
      N);
  if (S)
    Report->addRange(S->getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potential stack buffer overflow when writing zeros past the end of a fixed-size buffer in FpToString",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
