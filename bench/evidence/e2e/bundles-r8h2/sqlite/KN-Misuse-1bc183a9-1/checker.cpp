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
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Map the tokenizer return value (token length) to the token-type
// out-parameter's memory region.
REGISTER_MAP_WITH_PROGRAMSTATE(TokenizerResultMap, SymbolRef, const MemRegion*)

// Track whether a token-type variable is still unguarded against the
// illegal-token sentinel.
REGISTER_MAP_WITH_PROGRAMSTATE(UnguardedTokenTypeMap, const MemRegion*, bool)

namespace {

static const VarDecl *getVarDeclFromExpr(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E))
    return dyn_cast<VarDecl>(DRE->getDecl());
  return nullptr;
}

static const VarDecl *getVarDeclFromRegion(const MemRegion *MR) {
  if (!MR)
    return nullptr;
  if (const VarRegion *VR = dyn_cast<VarRegion>(MR))
    return VR->getDecl();
  return nullptr;
}

static const MemRegion *getRegionForVar(const VarDecl *VD,
                                        ProgramStateRef State,
                                        CheckerContext &C) {
  if (!VD)
    return nullptr;
  const VarRegion *VR = State->getRegion(VD, C.getLocationContext());
  return VR ? VR->getBaseRegion() : nullptr;
}

static bool isIllegalSentinelExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    const NamedDecl *ND = DRE->getDecl();
    if (ND && knighter::isRole("illegal_token_sentinel",
                               ND->getNameAsString()))
      return true;
  }

  // The sentinel may be a macro in some projects, so also check the source
  // spelling against the illegal-token-sentinel role names.
  for (const std::string &Name :
       knighter::roleNames("illegal_token_sentinel")) {
    if (ExprHasName(E, Name, C))
      return true;
  }

  return false;
}

static void markUnguardedFalseInCondition(const Expr *E,
                                          CheckerContext &C,
                                          ProgramStateRef &State) {
  if (!E)
    return;

  E = E->IgnoreParenImpCasts();

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    BinaryOperator::Opcode Op = BO->getOpcode();

    if (Op == BO_LAnd || Op == BO_LOr) {
      markUnguardedFalseInCondition(BO->getLHS(), C, State);
      markUnguardedFalseInCondition(BO->getRHS(), C, State);
      return;
    }

    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS();
      const Expr *RHS = BO->getRHS();
      const Expr *VarExpr = nullptr;

      if (isIllegalSentinelExpr(LHS, C)) {
        VarExpr = RHS;
      } else if (isIllegalSentinelExpr(RHS, C)) {
        VarExpr = LHS;
      }

      if (VarExpr) {
        if (const VarDecl *VD = getVarDeclFromExpr(VarExpr)) {
          if (const MemRegion *MR = getRegionForVar(VD, State, C)) {
            State = State->set<UnguardedTokenTypeMap>(MR, false);
          }
        }
      }
    }
  }
}

static bool isVarPassedAsArg(const CallEvent &Call,
                             const VarDecl *VD,
                             CheckerContext &C) {
  if (!VD)
    return false;

  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    const Expr *ArgE = Call.getArgExpr(I);
    if (!ArgE)
      continue;

    const Expr *E = ArgE->IgnoreParenImpCasts();

    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (DRE->getDecl() == VD)
        return true;
    }

    if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_AddrOf) {
        const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
        if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub)) {
          if (DRE->getDecl() == VD)
            return true;
        }
      }
    }
  }

  return false;
}

static const MemRegion *getOutParamRegionFromCall(const CallEvent &Call,
                                                  CheckerContext &C) {
  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    const Expr *ArgE = Call.getArgExpr(I);
    if (!ArgE)
      continue;

    const Expr *E = ArgE->IgnoreParenImpCasts();
    const UnaryOperator *UO = dyn_cast<UnaryOperator>(E);
    if (!UO || UO->getOpcode() != UO_AddrOf)
      continue;

    const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub)) {
      if (isa<VarDecl>(DRE->getDecl())) {
        const MemRegion *MR = getMemRegionFromExpr(ArgE, C);
        if (MR)
          return MR->getBaseRegion();
      }
    }
  }

  return nullptr;
}

class SAGenTestChecker
    : public Checker<check::PostCall,
                     check::PreCall,
                     check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this,
                       "Missing illegal-token guard",
                       "Tokenizer error handling")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "tokenizer"))
    return;

  SVal RetVal = Call.getReturnValue();
  SymbolRef RetSym = RetVal.getAsSymbol();
  if (!RetSym)
    return;

  const MemRegion *OutRegion = getOutParamRegionFromCall(Call, C);
  if (!OutRegion)
    return;

  ProgramStateRef State = C.getState();
  State = State->set<TokenizerResultMap>(RetSym, OutRegion);
  State = State->set<UnguardedTokenTypeMap>(OutRegion, true);
  C.addTransition(State);
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "dequote_helper"))
    return;

  ProgramStateRef State = C.getState();

  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    SVal ArgVal = Call.getArgSVal(I);
    SymbolRef Sym = ArgVal.getAsSymbol();
    if (!Sym)
      continue;

    const MemRegion * const *OutRegionPtr =
        State->get<TokenizerResultMap>(Sym);
    if (!OutRegionPtr)
      continue;

    const MemRegion *OutRegion = *OutRegionPtr;

    // If the helper already receives the token-type value, it can handle the
    // illegal-token sentinel itself.
    const VarDecl *OutVD = getVarDeclFromRegion(OutRegion);
    if (isVarPassedAsArg(Call, OutVD, C))
      continue;

    const bool *Unguarded = State->get<UnguardedTokenTypeMap>(OutRegion);
    if (Unguarded && *Unguarded) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;

      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT,
          "token type may be illegal; missing guard before dequoting",
          N);
      Report->addRange(Call.getSourceRange());
      C.emitReport(std::move(Report));
      return;
    }
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast_or_null<Expr>(Condition);
  if (!CondE)
    return;

  ProgramStateRef State = C.getState();
  markUnguardedFalseInCondition(CondE, C, State);
  C.addTransition(State);
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing illegal-token guards before dequoting token text",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "tokenizer": {
    "names": ["getConstraintToken", "sqlite3GetToken"],
    "description": "returns a token length and writes a token type to an out-parameter; can return an illegal-token sentinel for corrupt input"
  },
  "dequote_helper": {
    "names": ["quotedCompare"],
    "description": "helper that copies token text and dequotes it, assuming the token is syntactically valid"
  },
  "illegal_token_sentinel": {
    "names": ["TK_ILLEGAL"],
    "description": "token type value indicating the tokenizer encountered illegal/corrupt input"
  },
  "dequoter_with_precondition": {
    "names": ["sqlite3Dequote"],
    "description": "dequoter that has a precondition/assertion for valid quoted tokens"
  },
  "caller_ignoring_sentinel": {
    "names": ["findConstraintFunc", "dropConstraintFunc"],
    "description": "caller that ignores the tokenizer's illegal-token sentinel before invoking the dequote helper"
  }
}
*/
