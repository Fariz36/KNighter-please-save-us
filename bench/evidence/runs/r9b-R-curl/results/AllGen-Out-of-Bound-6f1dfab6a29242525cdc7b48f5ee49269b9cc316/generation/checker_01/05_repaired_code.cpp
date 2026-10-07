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
#include "llvm/Support/Casting.h"
#include "llvm/ADT/SmallVector.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

// Program state maps
REGISTER_MAP_WITH_PROGRAMSTATE(NulInputMap, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(DelimSearchMap, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(AdvancedMap, const MemRegion *, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(OffsetCharMap, const MemRegion *, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::PostStmt<DeclStmt>,
                                        check::Bind,
                                        check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read after delimiter",
                       "Memory error")) {}

  void checkPostStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;

private:
  bool containsRoleCall(const Expr *E, StringRef Role,
                        ASTContext &Ctx) const;
  bool isDerivedFromNulInput(const Expr *E, CheckerContext &C) const;
  bool getZeroOffsetAccess(const Expr *E, CheckerContext &C,
                           const MemRegion *&PtrRegion) const;
  bool isNonZeroGuard(const Expr *E, const MemRegion *V,
                      CheckerContext &C) const;
  bool exprRefersToRegion(const Expr *E, const MemRegion *V,
                          CheckerContext &C) const;
  bool containsReadP_i_gt_0(const Expr *E, const MemRegion *P,
                            CheckerContext &C) const;
  bool findCharClassifierRead(const Expr *E, CheckerContext &C,
                              const MemRegion *&P) const;
  void collectAndOperands(const Expr *E,
                          llvm::SmallVectorImpl<const Expr *> &Ops) const;
  const Expr *getRHSExpr(const Stmt *S) const;
};

} // end anonymous namespace

//===----------------------------------------------------------------------===//
// Helper implementations
//===----------------------------------------------------------------------===//

bool SAGenTestChecker::containsRoleCall(const Expr *E, StringRef Role,
                                        ASTContext &Ctx) const {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const CallExpr *CE = dyn_cast<CallExpr>(E)) {
    if (knighter::callExprIsRole(CE, Role, Ctx))
      return true;
  }

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    return containsRoleCall(BO->getLHS(), Role, Ctx) ||
           containsRoleCall(BO->getRHS(), Role, Ctx);
  }
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    return containsRoleCall(UO->getSubExpr(), Role, Ctx);
  }
  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    return containsRoleCall(ASE->getBase(), Role, Ctx) ||
           containsRoleCall(ASE->getIdx(), Role, Ctx);
  }
  if (const CastExpr *CE = dyn_cast<CastExpr>(E)) {
    return containsRoleCall(CE->getSubExpr(), Role, Ctx);
  }
  if (const ParenExpr *PE = dyn_cast<ParenExpr>(E)) {
    return containsRoleCall(PE->getSubExpr(), Role, Ctx);
  }
  if (const MemberExpr *ME = dyn_cast<MemberExpr>(E)) {
    return containsRoleCall(ME->getBase(), Role, Ctx);
  }
  return false;
}

bool SAGenTestChecker::isDerivedFromNulInput(const Expr *E,
                                             CheckerContext &C) const {
  if (!E)
    return false;
  if (containsRoleCall(E, "parser_input", C.getASTContext()))
    return true;
  SVal Val = C.getState()->getSVal(E, C.getLocationContext());
  if (const MemRegion *MR = Val.getAsRegion()) {
    return C.getState()->get<NulInputMap>(MR->getBaseRegion());
  }
  return false;
}

bool SAGenTestChecker::getZeroOffsetAccess(const Expr *E, CheckerContext &C,
                                           const MemRegion *&PtrRegion) const {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    const Expr *Idx = ASE->getIdx()->IgnoreParenImpCasts();
    llvm::APSInt IdxVal;
    if (EvaluateExprToInt(IdxVal, Idx, C) && IdxVal == 0) {
      SVal BaseVal = C.getState()->getSVal(ASE->getBase(),
                                           C.getLocationContext());
      if (const MemRegion *MR = BaseVal.getAsRegion()) {
        PtrRegion = MR->getBaseRegion();
        return true;
      }
    }
  } else if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      SVal BaseVal = C.getState()->getSVal(UO->getSubExpr(),
                                           C.getLocationContext());
      if (const MemRegion *MR = BaseVal.getAsRegion()) {
        PtrRegion = MR->getBaseRegion();
        return true;
      }
    }
  }
  return false;
}

bool SAGenTestChecker::exprRefersToRegion(const Expr *E, const MemRegion *V,
                                          CheckerContext &C) const {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (VD) {
      const MemRegion *MR = C.getState()->getRegion(VD, C.getLocationContext());
      return MR == V;
    }
  }
  return false;
}

bool SAGenTestChecker::isNonZeroGuard(const Expr *E, const MemRegion *V,
                                      CheckerContext &C) const {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (exprRefersToRegion(E, V, C))
    return true;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LHSIsV = exprRefersToRegion(LHS, V, C);
      bool RHSIsV = exprRefersToRegion(RHS, V, C);
      auto isZeroConst = [&](const Expr *E) -> bool {
        llvm::APSInt Val;
        if (EvaluateExprToInt(Val, E, C))
          return Val == 0;
        if (const CharacterLiteral *CL = dyn_cast<CharacterLiteral>(E)) {
          return CL->getValue() == 0;
        }
        return false;
      };
      if (LHSIsV && isZeroConst(RHS))
        return true;
      if (RHSIsV && isZeroConst(LHS))
        return true;
    }
  }
  return false;
}

bool SAGenTestChecker::containsReadP_i_gt_0(const Expr *E, const MemRegion *P,
                                            CheckerContext &C) const {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    SVal BaseVal = C.getState()->getSVal(ASE->getBase(),
                                         C.getLocationContext());
    if (const MemRegion *BaseMR = BaseVal.getAsRegion()) {
      if (BaseMR->getBaseRegion() == P) {
        llvm::APSInt IdxVal;
        if (EvaluateExprToInt(IdxVal, ASE->getIdx(), C)) {
          if (IdxVal > 0)
            return true;
        }
      }
    }
  }

  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UO_Deref) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Sub)) {
        if (BO->getOpcode() == BO_Add) {
          const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
          const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
          SVal LHSVal = C.getState()->getSVal(LHS, C.getLocationContext());
          SVal RHSVal = C.getState()->getSVal(RHS, C.getLocationContext());
          const MemRegion *LHSMR = LHSVal.getAsRegion();
          const MemRegion *RHSMR = RHSVal.getAsRegion();
          if (LHSMR && LHSMR->getBaseRegion() == P) {
            llvm::APSInt RHSInt;
            if (EvaluateExprToInt(RHSInt, RHS, C) && RHSInt > 0)
              return true;
          }
          if (RHSMR && RHSMR->getBaseRegion() == P) {
            llvm::APSInt LHSInt;
            if (EvaluateExprToInt(LHSInt, LHS, C) && LHSInt > 0)
              return true;
          }
        }
      }
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child)) {
      if (containsReadP_i_gt_0(ChildE, P, C))
        return true;
    }
  }
  return false;
}

bool SAGenTestChecker::findCharClassifierRead(const Expr *E, CheckerContext &C,
                                              const MemRegion *&P) const {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();

  if (const CallExpr *CE = dyn_cast<CallExpr>(E)) {
    if (knighter::callExprIsRole(CE, "char_classifier",
                                 C.getASTContext())) {
      if (CE->getNumArgs() > 0) {
        const Expr *Arg = CE->getArg(0)->IgnoreParenImpCasts();
        if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(Arg)) {
          SVal BaseVal = C.getState()->getSVal(ASE->getBase(),
                                               C.getLocationContext());
          if (const MemRegion *BaseMR = BaseVal.getAsRegion()) {
            llvm::APSInt IdxVal;
            if (EvaluateExprToInt(IdxVal, ASE->getIdx(), C) && IdxVal > 0) {
              P = BaseMR->getBaseRegion();
              return true;
            }
          }
        }
        if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(Arg)) {
          if (UO->getOpcode() == UO_Deref) {
            const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
            if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Sub)) {
              if (BO->getOpcode() == BO_Add) {
                const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
                const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
                SVal LHSVal = C.getState()->getSVal(LHS,
                                                    C.getLocationContext());
                SVal RHSVal = C.getState()->getSVal(RHS,
                                                    C.getLocationContext());
                const MemRegion *LHSMR = LHSVal.getAsRegion();
                const MemRegion *RHSMR = RHSVal.getAsRegion();
                if (LHSMR) {
                  llvm::APSInt RHSInt;
                  if (EvaluateExprToInt(RHSInt, RHS, C) && RHSInt > 0) {
                    P = LHSMR->getBaseRegion();
                    return true;
                  }
                }
                if (RHSMR) {
                  llvm::APSInt LHSInt;
                  if (EvaluateExprToInt(LHSInt, LHS, C) && LHSInt > 0) {
                    P = RHSMR->getBaseRegion();
                    return true;
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child)) {
      if (findCharClassifierRead(ChildE, C, P))
        return true;
    }
  }
  return false;
}

void SAGenTestChecker::collectAndOperands(
    const Expr *E, llvm::SmallVectorImpl<const Expr *> &Ops) const {
  if (!E)
    return;
  E = E->IgnoreParenImpCasts();
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      collectAndOperands(BO->getLHS(), Ops);
      collectAndOperands(BO->getRHS(), Ops);
      return;
    }
  }
  Ops.push_back(E);
}

const Expr *SAGenTestChecker::getRHSExpr(const Stmt *S) const {
  if (!S)
    return nullptr;
  if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
    if (DS->isSingleDecl()) {
      const VarDecl *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
      if (VD && VD->hasInit())
        return VD->getInit();
    }
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->isAssignmentOp())
      return BO->getRHS();
  }
  return nullptr;
}

//===----------------------------------------------------------------------===//
// Checker callbacks
//===----------------------------------------------------------------------===//

void SAGenTestChecker::checkPostStmt(const DeclStmt *DS,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  for (const Decl *D : DS->decls()) {
    const VarDecl *VD = dyn_cast<VarDecl>(D);
    if (!VD)
      continue;
    const Expr *Init = VD->getInit();
    if (!Init)
      continue;

    const MemRegion *VarReg = C.getState()->getRegion(VD, C.getLocationContext());
    if (!VarReg)
      continue;
    VarReg = VarReg->getBaseRegion();

    // Check for parser_input role
    if (containsRoleCall(Init, "parser_input", C.getASTContext())) {
      State = State->set<NulInputMap>(VarReg, true);
    }

    // Check for delimiter_search role
    const Expr *InitIgnored = Init->IgnoreParenImpCasts();
    if (const CallExpr *CE = dyn_cast<CallExpr>(InitIgnored)) {
      if (knighter::callExprIsRole(CE, "delimiter_search",
                                   C.getASTContext())) {
        if (CE->getNumArgs() > 0) {
          const Expr *Arg0 = CE->getArg(0);
          if (isDerivedFromNulInput(Arg0, C)) {
            State = State->set<DelimSearchMap>(VarReg, true);
          }
        }
      }
    }
  }
  C.addTransition(State);
}

void SAGenTestChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *LHSReg = Loc.getAsRegion();
  if (!LHSReg)
    return;
  LHSReg = LHSReg->getBaseRegion();
  if (!LHSReg)
    return;

  const Expr *RHS = getRHSExpr(S);

  // 1. If RHS is a delimiter_search role call on a NulInputMap source,
  //    add LHS to DelimSearchMap.
  if (RHS) {
    const Expr *RHSIgnored = RHS->IgnoreParenImpCasts();
    if (const CallExpr *CE = dyn_cast<CallExpr>(RHSIgnored)) {
      if (knighter::callExprIsRole(CE, "delimiter_search",
                                   C.getASTContext())) {
        if (CE->getNumArgs() > 0) {
          const Expr *Arg0 = CE->getArg(0);
          if (isDerivedFromNulInput(Arg0, C)) {
            State = State->set<DelimSearchMap>(LHSReg, true);
          }
        }
      }
    }
  }

  // 2. If LHS is in DelimSearchMap and statement is an increment, add to
  //    AdvancedMap.
  if (State->get<DelimSearchMap>(LHSReg)) {
    bool isIncrement = false;
    if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(S)) {
      if (UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc)
        isIncrement = true;
    } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->getOpcode() == BO_AddAssign) {
        llvm::APSInt RHSInt;
        if (EvaluateExprToInt(RHSInt, BO->getRHS(), C) && RHSInt == 1)
          isIncrement = true;
      } else if (BO->getOpcode() == BO_Assign) {
        const Expr *RHSExpr = BO->getRHS()->IgnoreParenImpCasts();
        if (const BinaryOperator *Add = dyn_cast<BinaryOperator>(RHSExpr)) {
          if (Add->getOpcode() == BO_Add) {
            SVal LHSVal = State->getSVal(Add->getLHS(),
                                         C.getLocationContext());
            SVal RHSVal = State->getSVal(Add->getRHS(),
                                         C.getLocationContext());
            const MemRegion *LHSMR = LHSVal.getAsRegion();
            const MemRegion *RHSMR = RHSVal.getAsRegion();
            if (LHSMR && LHSMR->getBaseRegion() == LHSReg) {
              llvm::APSInt RHSInt;
              if (EvaluateExprToInt(RHSInt, Add->getRHS(), C) && RHSInt == 1)
                isIncrement = true;
            }
            if (RHSMR && RHSMR->getBaseRegion() == LHSReg) {
              llvm::APSInt LHSInt;
              if (EvaluateExprToInt(LHSInt, Add->getLHS(), C) && LHSInt == 1)
                isIncrement = true;
            }
          }
        }
      }
    }
    if (isIncrement) {
      State = State->set<AdvancedMap>(LHSReg, true);
    }
  }

  // 3. If RHS is P[0] or *P, where P is in AdvancedMap, set
  //    OffsetCharMap[P] = LHSReg.
  if (RHS) {
    const MemRegion *P = nullptr;
    if (getZeroOffsetAccess(RHS, C, P)) {
      if (State->get<AdvancedMap>(P)) {
        State = State->set<OffsetCharMap>(P, LHSReg);
      }
    }
  }

  // 4. If LHS is a pointer variable and RHS derives from parser_input role
  //    call, add LHS to NulInputMap.
  if (RHS && containsRoleCall(RHS, "parser_input", C.getASTContext())) {
    State = State->set<NulInputMap>(LHSReg, true);
  }

  C.addTransition(State);
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE)
    return;

  const MemRegion *P = nullptr;
  if (!findCharClassifierRead(CondE, C, P))
    return;

  ProgramStateRef State = C.getState();
  if (!State->get<AdvancedMap>(P))
    return;

  const MemRegion *V = nullptr;
  if (const MemRegion *const *VP = State->get<OffsetCharMap>(P))
    V = *VP;
  if (!V)
    return;

  llvm::SmallVector<const Expr *, 8> Ops;
  collectAndOperands(CondE, Ops);

  bool guardSeen = false;
  for (const Expr *Op : Ops) {
    if (isNonZeroGuard(Op, V, C)) {
      guardSeen = true;
      continue;
    }
    if (containsReadP_i_gt_0(Op, P, C)) {
      if (!guardSeen) {
        ExplodedNode *N = C.generateNonFatalErrorNode();
        if (!N)
          return;
        auto report = std::make_unique<PathSensitiveBugReport>(
            *BT,
            "Possible out-of-bounds read: missing non-zero check after "
            "delimiter",
            N);
        report->addRange(Op->getSourceRange());
        C.emitReport(std::move(report));
        return;
      } else {
        return;
      }
    }
  }
}

//===----------------------------------------------------------------------===//
// Checker registration
//===----------------------------------------------------------------------===//

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects out-of-bounds read when accessing characters after a delimiter "
      "without checking for NUL",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "parser_input": {"names": ["curlx_dyn_ptr"], "description": "returns a pointer to a NUL-terminated input buffer to be parsed"},
  "delimiter_search": {"names": ["strchr"], "description": "searches a NUL-terminated string for a delimiter and returns a pointer into that string"},
  "char_classifier": {"names": ["ISDIGIT"], "description": "tests a character value for a class; its argument must be a valid byte from the string"}
}
*/
