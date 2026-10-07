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
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

struct DivisionCandidate {
  const BinaryOperator *Div;
  const FieldDecl *Field;
  SourceLocation Loc;
};

// -----------------------------------------------------------------------------
// AST helpers
// -----------------------------------------------------------------------------

static const FieldDecl *getFieldFromExpr(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *ME = dyn_cast<MemberExpr>(E)) {
    if (const auto *FD = dyn_cast<FieldDecl>(ME->getMemberDecl()))
      return FD;
  }
  return nullptr;
}

static const ParmVarDecl *getParamFromExpr(const Expr *E) {
  if (!E)
    return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const auto *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl()))
      return PVD;
  }
  return nullptr;
}

static bool exprRefersTo(const Expr *E, const ValueDecl *VD) {
  if (!E || !VD)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
    return DRE->getDecl() == VD;
  if (const auto *ME = dyn_cast<MemberExpr>(E))
    return ME->getMemberDecl() == VD;
  return false;
}

static bool isZeroLiteral(const Expr *E, ASTContext &AC) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (E->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull))
    return true;
  Expr::EvalResult Res;
  if (E->EvaluateAsInt(Res, AC))
    return Res.Val.getInt() == 0;
  return false;
}

static bool isOneLiteral(const Expr *E, ASTContext &AC) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  Expr::EvalResult Res;
  if (E->EvaluateAsInt(Res, AC))
    return Res.Val.getInt() == 1;
  return false;
}

static bool isZeroComparison(const Expr *Cond, const ValueDecl *VD,
                             ASTContext &AC);
static bool isNonZeroComparison(const Expr *Cond, const ValueDecl *VD,
                                ASTContext &AC);

static bool isZeroComparison(const Expr *Cond, const ValueDecl *VD,
                             ASTContext &AC) {
  if (!Cond || !VD)
    return false;
  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (exprRefersTo(Sub, VD))
        return true;
      if (isNonZeroComparison(Sub, VD, AC))
        return true;
    }
  }

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    const auto Op = BO->getOpcode();
    const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

    const bool LRef = exprRefersTo(L, VD);
    const bool RRef = exprRefersTo(R, VD);
    const bool LZero = isZeroLiteral(L, AC);
    const bool RZero = isZeroLiteral(R, AC);
    const bool LOne = isOneLiteral(L, AC);
    const bool ROne = isOneLiteral(R, AC);

    if (Op == BO_EQ) {
      if (LRef && RZero)
        return true;
      if (RRef && LZero)
        return true;
    }
    if (Op == BO_LE) {
      if (LRef && RZero) // x <= 0
        return true;
    }
    if (Op == BO_GE) {
      if (RRef && LZero) // 0 >= x
        return true;
    }
    if (Op == BO_LT) {
      if (LRef && ROne) // x < 1
        return true;
    }
    if (Op == BO_GT) {
      if (RRef && LOne) // 1 > x
        return true;
    }
  }

  return false;
}

static bool isNonZeroComparison(const Expr *Cond, const ValueDecl *VD,
                                ASTContext &AC) {
  if (!Cond || !VD)
    return false;
  Cond = Cond->IgnoreParenImpCasts();

  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (isZeroComparison(Sub, VD, AC))
        return true;
    }
  }

  // Bare variable used as a boolean condition.
  if (exprRefersTo(Cond, VD))
    return true;

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    const auto Op = BO->getOpcode();
    const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

    const bool LRef = exprRefersTo(L, VD);
    const bool RRef = exprRefersTo(R, VD);
    const bool LZero = isZeroLiteral(L, AC);
    const bool RZero = isZeroLiteral(R, AC);
    const bool LOne = isOneLiteral(L, AC);
    const bool ROne = isOneLiteral(R, AC);

    if (Op == BO_NE) {
      if (LRef && RZero)
        return true;
      if (RRef && LZero)
        return true;
    }
    if (Op == BO_GT) {
      if (LRef && RZero) // x > 0
        return true;
      if (LZero && RRef) // 0 > x
        return true;
    }
    if (Op == BO_LT) {
      if (LRef && RZero) // x < 0
        return true;
      if (LZero && RRef) // 0 < x
        return true;
    }
    if (Op == BO_GE) {
      if (LRef && ROne) // x >= 1
        return true;
    }
    if (Op == BO_LE) {
      if (LOne && RRef) // 1 <= x
        return true;
    }
  }

  return false;
}

static bool conditionGuaranteesZero(const Expr *Cond, const ValueDecl *VD,
                                    ASTContext &AC) {
  if (!Cond || !VD)
    return false;
  Cond = Cond->IgnoreParenImpCasts();

  if (isZeroComparison(Cond, VD, AC))
    return true;

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_LAnd) {
      return conditionGuaranteesZero(BO->getLHS(), VD, AC) ||
             conditionGuaranteesZero(BO->getRHS(), VD, AC);
    }
    if (BO->getOpcode() == BO_LOr) {
      return conditionGuaranteesZero(BO->getLHS(), VD, AC) &&
             conditionGuaranteesZero(BO->getRHS(), VD, AC);
    }
  }
  return false;
}

static bool conditionGuaranteesNonZero(const Expr *Cond, const ValueDecl *VD,
                                       ASTContext &AC) {
  if (!Cond || !VD)
    return false;
  Cond = Cond->IgnoreParenImpCasts();

  if (isNonZeroComparison(Cond, VD, AC))
    return true;

  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_LAnd) {
      return conditionGuaranteesNonZero(BO->getLHS(), VD, AC) ||
             conditionGuaranteesNonZero(BO->getRHS(), VD, AC);
    }
    if (BO->getOpcode() == BO_LOr) {
      return conditionGuaranteesNonZero(BO->getLHS(), VD, AC) &&
             conditionGuaranteesNonZero(BO->getRHS(), VD, AC);
    }
  }
  return false;
}

static bool stmtAlwaysExits(const Stmt *S) {
  if (!S)
    return false;

  if (isa<ReturnStmt>(S) || isa<BreakStmt>(S) || isa<ContinueStmt>(S) ||
      isa<GotoStmt>(S))
    return true;

  if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
    for (const Stmt *Child : CS->body()) {
      if (stmtAlwaysExits(Child))
        return true;
    }
    return false;
  }

  if (const auto *IS = dyn_cast<IfStmt>(S)) {
    return IS->getElse() && stmtAlwaysExits(IS->getThen()) &&
           stmtAlwaysExits(IS->getElse());
  }

  return false;
}

static bool hasEarlyZeroExitBefore(const CompoundStmt *CS, const Stmt *Child,
                                   const ValueDecl *VD, ASTContext &AC) {
  if (!CS || !Child || !VD)
    return false;

  for (const Stmt *S : CS->body()) {
    if (S == Child)
      break;
    if (const auto *IS = dyn_cast<IfStmt>(S)) {
      if (conditionGuaranteesZero(IS->getCond(), VD, AC) &&
          stmtAlwaysExits(IS->getThen()))
        return true;
    }
  }
  return false;
}

static const Stmt *getParentStmt(const Stmt *S, ASTContext &AC) {
  if (!S)
    return nullptr;
  auto Parents = AC.getParents(DynTypedNode::create(*S));
  for (const auto &Parent : Parents) {
    if (const Stmt *PS = Parent.get<Stmt>())
      return PS;
  }
  return nullptr;
}

static bool setterRejectsZero(const ParmVarDecl *Param,
                              const BinaryOperator *Assign,
                              ASTContext &AC) {
  if (!Param || !Assign)
    return false;

  const Stmt *Child = Assign;
  const Stmt *S = Assign;

  while (S) {
    const Stmt *Parent = getParentStmt(S, AC);
    if (!Parent)
      break;

    if (const auto *IS = dyn_cast<IfStmt>(Parent)) {
      if (IS->getThen() == Child) {
        if (conditionGuaranteesNonZero(IS->getCond(), Param, AC))
          return true;
      } else if (IS->getElse() == Child) {
        if (conditionGuaranteesZero(IS->getCond(), Param, AC))
          return true;
      }
    }

    if (const auto *CS = dyn_cast<CompoundStmt>(Parent)) {
      if (hasEarlyZeroExitBefore(CS, Child, Param, AC))
        return true;
    }

    Child = Parent;
    S = Parent;
  }

  return false;
}

static bool hasZeroGuard(const BinaryOperator *Div, const FieldDecl *Field,
                         ASTContext &AC) {
  if (!Div || !Field)
    return false;

  const Stmt *Child = Div;
  const Stmt *S = Div;

  while (S) {
    const Stmt *Parent = getParentStmt(S, AC);
    if (!Parent)
      break;

    if (const auto *BO = dyn_cast<BinaryOperator>(Parent)) {
      if (BO->getOpcode() == BO_LAnd && BO->getRHS() == Child) {
        if (conditionGuaranteesNonZero(BO->getLHS(), Field, AC))
          return true;
      }
    }

    if (const auto *IS = dyn_cast<IfStmt>(Parent)) {
      if (IS->getThen() == Child) {
        if (conditionGuaranteesNonZero(IS->getCond(), Field, AC))
          return true;
      } else if (IS->getElse() == Child) {
        if (conditionGuaranteesZero(IS->getCond(), Field, AC))
          return true;
      }
    }

    if (const auto *CS = dyn_cast<CompoundStmt>(Parent)) {
      if (hasEarlyZeroExitBefore(CS, Child, Field, AC))
        return true;
    }

    Child = Parent;
    S = Parent;
  }

  return false;
}

// -----------------------------------------------------------------------------
// AST visitors
// -----------------------------------------------------------------------------

class SetterVisitor : public RecursiveASTVisitor<SetterVisitor> {
  const FunctionDecl *FD;
  ASTContext &AC;
  llvm::DenseSet<const FieldDecl *> &ZeroAcceptingDivisorFields;

public:
  SetterVisitor(const FunctionDecl *FD, ASTContext &AC,
                llvm::DenseSet<const FieldDecl *> &ZeroAccepting)
      : FD(FD), AC(AC), ZeroAcceptingDivisorFields(ZeroAccepting) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Assign)
      return true;

    const FieldDecl *Field = getFieldFromExpr(BO->getLHS());
    if (!Field || !knighter::declIsRole(Field, "divisor_field"))
      return true;

    const ParmVarDecl *Param = getParamFromExpr(BO->getRHS());
    if (!Param)
      return true;

    if (!setterRejectsZero(Param, BO, AC))
      ZeroAcceptingDivisorFields.insert(Field);

    return true;
  }
};

class DivisionVisitor : public RecursiveASTVisitor<DivisionVisitor> {
  ASTContext &AC;
  llvm::SmallVectorImpl<DivisionCandidate> &UnguardedDivisions;

public:
  DivisionVisitor(ASTContext &AC,
                  llvm::SmallVectorImpl<DivisionCandidate> &Unguarded)
      : AC(AC), UnguardedDivisions(Unguarded) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Div)
      return true;

    const FieldDecl *Field = getFieldFromExpr(BO->getRHS());
    if (!Field || !knighter::declIsRole(Field, "divisor_field"))
      return true;

    if (!hasZeroGuard(BO, Field, AC)) {
      UnguardedDivisions.push_back(
          DivisionCandidate{BO, Field, BO->getExprLoc()});
    }

    return true;
  }
};

} // end anonymous namespace

namespace {

class SAGenTestChecker
    : public Checker<check::ASTCodeBody, check::EndAnalysis> {
  mutable std::unique_ptr<BugType> BT;

  mutable llvm::DenseSet<const FieldDecl *> ZeroAcceptingDivisorFields;
  mutable llvm::SmallVector<DivisionCandidate, 8> UnguardedDivisions;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Division by zero", "Arithmetic")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                        ExprEngine &Eng) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  ASTContext &AC = Mgr.getASTContext();

  // Part A: detect config setters that accept zero for divisor fields.
  if (knighter::declIsRole(FD, "config_setter")) {
    SetterVisitor SV(FD, AC, ZeroAcceptingDivisorFields);
    SV.TraverseStmt(FD->getBody());
  }

  // Part B: detect unguarded divisions by divisor fields.
  DivisionVisitor DV(AC, UnguardedDivisions);
  DV.TraverseStmt(FD->getBody());
}

void SAGenTestChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                                        ExprEngine &Eng) const {
  for (const DivisionCandidate &Cand : UnguardedDivisions) {
    if (!ZeroAcceptingDivisorFields.contains(Cand.Field))
      continue;

    auto Report = std::make_unique<BasicBugReport>(
        *BT,
        "Potential division by zero: divisor may be zero because config "
        "setter does not reject zero.",
        PathDiagnosticLocation(Cand.Loc, BR.getSourceManager()));
    Report->addRange(Cand.Div->getSourceRange());
    BR.emitReport(std::move(Report));
  }

  ZeroAcceptingDivisorFields.clear();
  UnguardedDivisions.clear();
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects division by zero caused by zero-accepting config setters for "
      "divisor fields",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "config_setter": {
    "names": ["xmlCtxtSetMaxAmplification"],
    "description": "function that stores a configuration argument into a field; if the stored value is later used as a divisor, the setter must reject zero"
  },
  "divisor_field": {
    "names": ["maxAmpl"],
    "description": "configuration field used as a divisor in arithmetic; it must be guaranteed non-zero before every division"
  }
}
*/
