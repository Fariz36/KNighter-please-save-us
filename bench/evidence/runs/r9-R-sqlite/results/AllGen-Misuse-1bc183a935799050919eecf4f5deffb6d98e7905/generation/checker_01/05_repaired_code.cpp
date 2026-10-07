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

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/Casting.h"

using namespace clang;
using namespace ento;

// Program state maps/sets for tracking token length/type association.
REGISTER_MAP_WITH_PROGRAMSTATE(LengthToTypeRegionMap, SymbolRef, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(TypeSymToRegionMap, SymbolRef, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(ParamTypeAliasMap, const MemRegion *, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(CheckedTypeRegions, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::PostCall,
                                        check::Location,
                                        check::Bind,
                                        check::BranchCondition,
                                        check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked token type", "Security")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *StoreE, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  static bool isTokenTypeRegion(ProgramStateRef State, const MemRegion *R);
  static const MemRegion *getTokenTypeRegion(const CallEvent &Call, CheckerContext &C);
  static void collectVarRegions(const Stmt *S, ProgramStateRef State,
                                const LocationContext *LCtx,
                                llvm::SmallVectorImpl<const MemRegion *> &Regions);
};

} // end anonymous namespace

// Returns true if R is one of the token-type regions recorded in
// LengthToTypeRegionMap.
bool SAGenTestChecker::isTokenTypeRegion(ProgramStateRef State,
                                         const MemRegion *R) {
  if (!R)
    return false;
  const auto &Map = State->get<LengthToTypeRegionMap>();
  for (const auto &Entry : Map) {
    if (Entry.second == R)
      return true;
  }
  return false;
}

// Find the pointer-to-integer argument of a parser_input call.  This is the
// out-parameter where the token type is written.
const MemRegion *SAGenTestChecker::getTokenTypeRegion(const CallEvent &Call,
                                                      CheckerContext &C) {
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;
    QualType QT = ArgE->getType();
    if (QT->isPointerType()) {
      QualType Pointee = QT->getPointeeType();
      if (Pointee->isIntegerType()) {
        SVal ArgVal = Call.getArgSVal(i);
        if (const MemRegion *R = ArgVal.getAsRegion())
          return R->getBaseRegion();
      }
    }
  }
  return nullptr;
}

// Collect all variable regions that appear in a condition expression.
void SAGenTestChecker::collectVarRegions(
    const Stmt *S, ProgramStateRef State, const LocationContext *LCtx,
    llvm::SmallVectorImpl<const MemRegion *> &Regions) {
  if (!S)
    return;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(S)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      SVal Loc = State->getLValue(VD, LCtx);
      if (const MemRegion *MR = Loc.getAsRegion())
        Regions.push_back(MR->getBaseRegion());
    }
  }
  for (const Stmt *Child : S->children())
    collectVarRegions(Child, State, LCtx, Regions);
}

// Record the association between a token length returned by parser_input and
// the region holding the corresponding token type.
void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "parser_input"))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef L = RetVal.getAsSymbol();
  if (!L)
    return;

  const MemRegion *R = getTokenTypeRegion(Call, C);
  if (!R)
    return;

  // A new token type value is written to R, so any previous check on R is no
  // longer valid.
  State = State->remove<CheckedTypeRegions>(R);
  State = State->set<LengthToTypeRegionMap>(L, R);
  C.addTransition(State);
}

// When a token type value is loaded, remember which symbol represents it.
void SAGenTestChecker::checkLocation(SVal Location, bool IsLoad, const Stmt *S,
                                     CheckerContext &C) const {
  if (!IsLoad)
    return;

  ProgramStateRef State = C.getState();
  const MemRegion *R = Location.getAsRegion();
  if (!R)
    return;
  const MemRegion *BaseR = R->getBaseRegion();
  if (!isTokenTypeRegion(State, BaseR))
    return;

  SVal Loaded = State->getSVal(R);
  SymbolRef T = Loaded.getAsSymbol();
  if (!T)
    return;

  State = State->set<TypeSymToRegionMap>(T, BaseR);
  C.addTransition(State);
}

// Propagate token-type regions through function parameters.
void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *StoreE,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const MemRegion *LocR = Loc.getAsRegion();
  if (!LocR)
    return;
  LocR = LocR->getBaseRegion();

  const auto *VR = dyn_cast<VarRegion>(LocR);
  if (!VR)
    return;
  const VarDecl *VD = VR->getDecl();
  if (!isa<ParmVarDecl>(VD))
    return;

  SymbolRef T = Val.getAsSymbol();
  if (!T)
    return;

  const MemRegion *const *OrigR = State->get<TypeSymToRegionMap>(T);
  if (!OrigR)
    return;

  State = State->set<ParamTypeAliasMap>(LocR, *OrigR);
  C.addTransition(State);
}

// Mark a token type as checked when it is read in a branch condition.
void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  llvm::SmallVector<const MemRegion *, 8> Regions;
  collectVarRegions(Condition, State, C.getLocationContext(), Regions);

  for (const MemRegion *MR : Regions) {
    // Resolve parameter aliases to the original token-type region.
    if (const MemRegion *const *Alias = State->get<ParamTypeAliasMap>(MR))
      MR = *Alias;

    if (isTokenTypeRegion(State, MR))
      State = State->add<CheckedTypeRegions>(MR);
  }

  C.addTransition(State);
}

// Detect a buffer_copy whose size argument is a token length whose associated
// token type was never checked.
void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "buffer_copy"))
    return;

  ProgramStateRef State = C.getState();

  // Find the integer argument that specifies the number of bytes to copy.
  int SizeIdx = -1;
  for (unsigned i = 0; i < Call.getNumArgs(); ++i) {
    const Expr *ArgE = Call.getArgExpr(i);
    if (!ArgE)
      continue;
    QualType QT = ArgE->getType();
    if (QT->isIntegerType())
      SizeIdx = i; // use the last integer argument
  }
  if (SizeIdx < 0)
    return;

  SVal SizeVal = Call.getArgSVal(SizeIdx);
  SymbolRef L = SizeVal.getAsSymbol();
  if (!L)
    return;

  const MemRegion *const *R = State->get<LengthToTypeRegionMap>(L);
  if (!R)
    return;

  const MemRegion *TokenTypeR = *R;
  if (State->contains<CheckedTypeRegions>(TokenTypeR))
    return;

  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT,
        "Token length used without checking token type; malformed input may "
        "reach dequoter.",
        N);
    Report->addRange(Call.getSourceRange());
    C.emitReport(std::move(Report));
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects token lengths used in buffer copies without checking the "
      "associated token type",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["getConstraintToken", "sqlite3GetToken"], "description": "tokenizes input text, returns token length and writes token type via an out-param"},
  "buffer_copy": {"names": ["memcpy"], "description": "copies a specified number of bytes from source to destination"},
  "allocator": {"names": ["sqlite3MallocZero"], "description": "allocates zero-initialized memory"},
  "aborting_assert": {"names": ["sqlite3Dequote"], "description": "dequotes a string and aborts via assert if the input is malformed"}
}
*/
