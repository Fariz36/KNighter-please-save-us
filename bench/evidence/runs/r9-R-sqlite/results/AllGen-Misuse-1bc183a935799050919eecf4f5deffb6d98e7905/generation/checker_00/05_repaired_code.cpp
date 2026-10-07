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
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

#include <optional>

using namespace clang;
using namespace ento;
using namespace taint;

// Taint tag for token type values that have not been validated.
static const TaintTagType TaintTag = 100;

// Maps the memory region of token text to the symbol representing its token type.
REGISTER_MAP_WITH_PROGRAMSTATE(TokenTextToTypeSymMap, const MemRegion *, SymbolRef)

namespace {

// Helper: recursively collect all DeclRefExprs inside a statement.
static void findDeclRefExprs(const Stmt *S,
                             llvm::SmallVectorImpl<const DeclRefExpr *> &Decls) {
  if (!S)
    return;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    Decls.push_back(DRE);
  }
  for (const Stmt *Child : S->children()) {
    findDeclRefExprs(Child, Decls);
  }
}

class SAGenTestChecker
    : public Checker<eval::Call,
                     check::PostCall,
                     check::BranchCondition,
                     check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked token type before dequoting",
                       "SQLite assertion failure")) {}

  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::evalCall(const CallEvent &Call,
                                CheckerContext &C) const {
  // Model parser_input functions: getConstraintToken, sqlite3GetToken.
  if (!knighter::callIsRole(Call, "parser_input"))
    return false;

  ProgramStateRef State = C.getState();
  const Expr *CE = Call.getOriginExpr();
  if (!CE)
    return false;

  unsigned NumArgs = Call.getNumArgs();
  if (NumArgs < 2)
    return false;

  const Expr *TextArg = Call.getArgExpr(0);
  const Expr *TypeArg = Call.getArgExpr(NumArgs - 1);
  if (!TextArg || !TypeArg)
    return false;

  // Get the base memory region of the token text.
  const MemRegion *TextReg = getMemRegionFromExpr(TextArg, C);
  if (!TextReg)
    return false;
  TextReg = TextReg->getBaseRegion();
  if (!TextReg)
    return false;

  // Determine the integer type of the token type out-parameter.
  QualType IntTy;
  if (const PointerType *PT = TypeArg->getType()->getAs<PointerType>()) {
    IntTy = PT->getPointeeType();
  }
  if (IntTy.isNull()) {
    IntTy = C.getASTContext().IntTy;
  }
  if (!IntTy->isIntegerType())
    return false;

  SValBuilder &SVB = C.getSValBuilder();
  const LocationContext *LCtx = C.getLocationContext();
  unsigned Count = C.blockCount();

  // Conjure a new symbol for the token type.
  SymbolRef TypeSym = SVB.conjureSymbol(CE, LCtx, IntTy, Count);
  if (!TypeSym)
    return false;
  SVal TypeVal = SVB.makeSymbolVal(TypeSym);

  // Bind the symbol to the pointee of TypeArg (typically &t).
  SVal TypeLocVal = State->getSVal(TypeArg, LCtx);
  if (auto TypeLoc = TypeLocVal.getAs<Loc>()) {
    State = State->bindLoc(*TypeLoc, TypeVal, LCtx);
  }

  // Mark the token type symbol as tainted (not yet validated).
  State = addTaint(State, TypeSym, TaintTag);

  // Associate the token text region with its token type symbol.
  State = State->set<TokenTextToTypeSymMap>(TextReg, TypeSym);

  // Conjure a return value for the token length.
  QualType RetTy = CE->getType();
  if (RetTy.isNull() || !RetTy->isIntegerType()) {
    RetTy = C.getASTContext().IntTy;
  }
  SymbolRef RetSym = SVB.conjureSymbol(CE, LCtx, RetTy, Count);
  if (RetSym) {
    SVal RetVal = SVB.makeSymbolVal(RetSym);
    State = State->BindExpr(CE, LCtx, RetVal);
  }

  C.addTransition(State);
  return true;
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  // Propagate token text association through memcpy.
  const IdentifierInfo *Callee = Call.getCalleeIdentifier();
  if (!Callee || Callee->getName() != "memcpy")
    return;

  ProgramStateRef State = C.getState();
  if (Call.getNumArgs() < 2)
    return;

  const Expr *DestExpr = Call.getArgExpr(0);
  const Expr *SrcExpr = Call.getArgExpr(1);
  if (!DestExpr || !SrcExpr)
    return;

  const MemRegion *DestReg = getMemRegionFromExpr(DestExpr, C);
  const MemRegion *SrcReg = getMemRegionFromExpr(SrcExpr, C);
  if (!DestReg || !SrcReg)
    return;

  DestReg = DestReg->getBaseRegion();
  SrcReg = SrcReg->getBaseRegion();
  if (!DestReg || !SrcReg)
    return;

  if (const SymbolRef *TypeSymPtr =
          State->get<TokenTextToTypeSymMap>(SrcReg)) {
    State = State->set<TokenTextToTypeSymMap>(DestReg, *TypeSymPtr);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  // When a branch condition uses the token type integer, consider it checked
  // and remove the taint so that subsequent dequoting is allowed.
  ProgramStateRef State = C.getState();
  llvm::SmallVector<const DeclRefExpr *, 8> Decls;
  findDeclRefExprs(Condition, Decls);

  for (const DeclRefExpr *DRE : Decls) {
    QualType Ty = DRE->getType();
    if (!Ty->isIntegerType())
      continue;

    SVal Val = State->getSVal(DRE, C.getLocationContext());
    if (SymbolRef Sym = Val.getAsSymbol()) {
      if (isTainted(State, Sym, TaintTag)) {
        State = removeTaint(State, Val);
      }
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  // Detect calls to a dequoter with token text whose token type was never
  // checked for validity (e.g. TK_ILLEGAL).
  if (!knighter::callIsRole(Call, "dequoter"))
    return;

  ProgramStateRef State = C.getState();
  if (Call.getNumArgs() < 1)
    return;

  const Expr *ArgExpr = Call.getArgExpr(0);
  if (!ArgExpr)
    return;

  const MemRegion *ArgReg = getMemRegionFromExpr(ArgExpr, C);
  if (!ArgReg)
    return;
  ArgReg = ArgReg->getBaseRegion();
  if (!ArgReg)
    return;

  const SymbolRef *TypeSymPtr = State->get<TokenTextToTypeSymMap>(ArgReg);
  if (!TypeSymPtr)
    return;
  SymbolRef TypeSym = *TypeSymPtr;

  if (isTainted(State, TypeSym, TaintTag)) {
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Dequoting token text without checking for illegal token type", N);
    Report->addRange(Call.getSourceRange());
    C.emitReport(std::move(Report));
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects dequoting token text without checking for illegal token type",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["getConstraintToken", "sqlite3GetToken"], "description": "parses input and returns a token length while setting a token type via an out-parameter"},
  "dequoter": {"names": ["sqlite3Dequote"], "description": "removes quote delimiters in place, assuming balanced/valid quoting"},
  "aborting_assert": {"names": ["assert"], "description": "macro that aborts execution when its condition is false"}
}
*/
