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
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

//===----------------------------------------------------------------------===//
// Helper functions
//===----------------------------------------------------------------------===//

static bool isParamRef(const Expr *E, const ParmVarDecl *P) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  const auto *DRE = dyn_cast<DeclRefExpr>(E);
  return DRE && DRE->getDecl() == P;
}

static bool getNullnessTest(const Expr *Cond, const ParmVarDecl *P,
                            bool &testsNonNull, bool &testsNull,
                            ASTContext &Ctx) {
  if (!Cond)
    return false;
  Cond = Cond->IgnoreParenImpCasts();

  // if (P)
  if (isParamRef(Cond, P)) {
    testsNonNull = true;
    return true;
  }

  // if (!P)
  if (const auto *UO = dyn_cast<UnaryOperator>(Cond)) {
    if (UO->getOpcode() == UO_LNot) {
      const Expr *Sub = UO->getSubExpr();
      if (isParamRef(Sub, P)) {
        testsNull = true;
        return true;
      }
    }
  }

  // if (P == NULL), if (P != NULL), etc.
  if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      bool LHSIsP = isParamRef(LHS, P);
      bool RHSIsP = isParamRef(RHS, P);
      bool LHSIsNull = LHS->isNullPointerConstant(
          Ctx, Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          Ctx, Expr::NPC_ValueDependentIsNull);

      if (LHSIsP && RHSIsNull) {
        if (BO->getOpcode() == BO_EQ)
          testsNull = true;
        else
          testsNonNull = true;
        return true;
      }
      if (RHSIsP && LHSIsNull) {
        if (BO->getOpcode() == BO_EQ)
          testsNull = true;
        else
          testsNonNull = true;
        return true;
      }
    }
  }
  return false;
}

static bool stmtAlwaysTerminates(const Stmt *S) {
  if (!S)
    return false;

  if (isa<ReturnStmt>(S) || isa<BreakStmt>(S) ||
      isa<ContinueStmt>(S) || isa<GotoStmt>(S))
    return true;

  if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
    for (const Stmt *Child : CS->body()) {
      if (stmtAlwaysTerminates(Child))
        return true;
    }
    return false;
  }

  if (const auto *IS = dyn_cast<IfStmt>(S)) {
    const Stmt *Else = IS->getElse();
    if (Else && stmtAlwaysTerminates(IS->getThen()) &&
        stmtAlwaysTerminates(Else))
      return true;
  }

  return false;
}

static bool hasNullCheckAndTerminates(const Stmt *S, const ParmVarDecl *P,
                                      ASTContext &Ctx) {
  const auto *IS = dyn_cast<IfStmt>(S);
  if (!IS)
    return false;

  bool testsNonNull = false;
  bool testsNull = false;
  if (!getNullnessTest(IS->getCond(), P, testsNonNull, testsNull, Ctx))
    return false;

  if (testsNull && stmtAlwaysTerminates(IS->getThen()))
    return true;

  if (testsNonNull && IS->getElse() && stmtAlwaysTerminates(IS->getElse()))
    return true;

  return false;
}

static const Stmt *getParentStmt(const Stmt *S, ASTContext &Ctx) {
  auto Parents = Ctx.getParentMapContext().getParents(*S);
  for (const auto &Parent : Parents) {
    if (const Stmt *PS = Parent.get<Stmt>())
      return PS;
  }
  return nullptr;
}

static bool isNullCheckedBefore(const ParmVarDecl *P, const CallExpr *SizeCall,
                                const FunctionDecl *FD, ASTContext &Ctx) {
  (void)FD;
  const Stmt *Child = SizeCall;

  while (true) {
    const Stmt *Parent = getParentStmt(Child, Ctx);
    if (!Parent)
      break;

    if (const auto *CS = dyn_cast<CompoundStmt>(Parent)) {
      for (const Stmt *S : CS->body()) {
        if (S == Child)
          break;
        if (hasNullCheckAndTerminates(S, P, Ctx))
          return true;
      }
    } else if (const auto *IS = dyn_cast<IfStmt>(Parent)) {
      const Stmt *Then = IS->getThen();
      const Stmt *Else = IS->getElse();
      bool inThen = (Child == Then);
      bool inElse = (Else && Child == Else);

      if (inThen || inElse) {
        bool testsNonNull = false;
        bool testsNull = false;
        if (getNullnessTest(IS->getCond(), P, testsNonNull, testsNull, Ctx)) {
          if (inThen && testsNonNull)
            return true;
          if (inElse && testsNull)
            return true;
        }
      }
    } else if (const auto *WS = dyn_cast<WhileStmt>(Parent)) {
      if (Child == WS->getBody()) {
        bool testsNonNull = false;
        bool testsNull = false;
        if (getNullnessTest(WS->getCond(), P, testsNonNull, testsNull, Ctx) &&
            testsNonNull)
          return true;
      }
    } else if (const auto *FS = dyn_cast<ForStmt>(Parent)) {
      if (Child == FS->getBody() && FS->getCond()) {
        bool testsNonNull = false;
        bool testsNull = false;
        if (getNullnessTest(FS->getCond(), P, testsNonNull, testsNull, Ctx) &&
            testsNonNull)
          return true;
      }
    }

    Child = Parent;
  }

  return false;
}

static const VarDecl *findAssignedVar(const CallExpr *SizeCall,
                                      ASTContext &Ctx) {
  const Expr *Cur = SizeCall;

  while (true) {
    auto Parents = Ctx.getParentMapContext().getParents(*Cur);
    if (Parents.empty())
      return nullptr;

    bool moved = false;

    for (const auto &Parent : Parents) {
      if (const Stmt *S = Parent.get<Stmt>()) {
        if (const auto *ICE = dyn_cast<ImplicitCastExpr>(S)) {
          Cur = ICE;
          moved = true;
          break;
        }
        if (const auto *PE = dyn_cast<ParenExpr>(S)) {
          Cur = PE;
          moved = true;
          break;
        }
        if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
          if (BO->getOpcode() == BO_Assign && BO->getRHS() == Cur) {
            const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
            if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
              if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
                return VD;
            }
          }
        }
      } else if (const auto *VD = Parent.get<VarDecl>()) {
        if (VD->getInit() && VD->getInit() == Cur)
          return VD;
      }
    }

    if (!moved)
      return nullptr;
  }
}

static bool exprContainsCallOrVar(const Expr *E, const CallExpr *SizeCall,
                                  const VarDecl *VD) {
  if (!E)
    return false;

  const Expr *Stripped = E->IgnoreParenImpCasts();

  if (Stripped == SizeCall)
    return true;

  if (const auto *DRE = dyn_cast<DeclRefExpr>(Stripped)) {
    if (VD && DRE->getDecl() == VD)
      return true;
  }

  for (const Stmt *Child : Stripped->children()) {
    if (const auto *ChildE = dyn_cast<Expr>(Child)) {
      if (exprContainsCallOrVar(ChildE, SizeCall, VD))
        return true;
    }
  }

  return false;
}

static bool isSizeUsedByReallocator(const CallExpr *SizeCall,
                                    ArrayRef<const CallExpr *> ReallocCalls,
                                    const FunctionDecl *FD, ASTContext &Ctx) {
  (void)FD;
  const VarDecl *AssignedVar = findAssignedVar(SizeCall, Ctx);

  for (const CallExpr *ReallocCall : ReallocCalls) {
    for (unsigned i = 0; i < ReallocCall->getNumArgs(); ++i) {
      const Expr *Arg = ReallocCall->getArg(i);
      if (exprContainsCallOrVar(Arg, SizeCall, AssignedVar))
        return true;
    }
  }

  return false;
}

class DerefCollector : public RecursiveASTVisitor<DerefCollector> {
  const FunctionDecl *FD;
  SmallVectorImpl<const ParmVarDecl *> &Params;
  SmallVectorImpl<const Expr *> &DerefExprs;

public:
  DerefCollector(const FunctionDecl *FD,
                 SmallVectorImpl<const ParmVarDecl *> &Params,
                 SmallVectorImpl<const Expr *> &DerefExprs)
      : FD(FD), Params(Params), DerefExprs(DerefExprs) {}

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (UO->getOpcode() == UO_Deref) {
      recordBase(UO->getSubExpr(), UO);
    }
    return true;
  }

  bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
    recordBase(ASE->getBase(), ASE);
    return true;
  }

  bool VisitMemberExpr(MemberExpr *ME) {
    if (ME->isArrow()) {
      recordBase(ME->getBase(), ME);
    }
    return true;
  }

private:
  void recordBase(const Expr *Base, const Expr *DerefExpr) {
    if (!Base)
      return;

    Base = Base->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Base)) {
      if (const auto *P = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
        if (P->getDeclContext() == FD && P->getType()->isPointerType()) {
          Params.push_back(P);
          DerefExprs.push_back(DerefExpr);
        }
      }
    }
  }
};

static void collectDereferencedParams(
    const Expr *E, const FunctionDecl *FD,
    SmallVectorImpl<const ParmVarDecl *> &Params,
    SmallVectorImpl<const Expr *> &DerefExprs) {
  if (!E)
    return;

  DerefCollector Collector(FD, Params, DerefExprs);
  Collector.TraverseStmt(const_cast<Expr *>(E));
}

class CallCollector : public RecursiveASTVisitor<CallCollector> {
  SmallVectorImpl<const CallExpr *> &SizeCalls;
  SmallVectorImpl<const CallExpr *> &ReallocCalls;

public:
  CallCollector(SmallVectorImpl<const CallExpr *> &SizeCalls,
                SmallVectorImpl<const CallExpr *> &ReallocCalls)
      : SizeCalls(SizeCalls), ReallocCalls(ReallocCalls) {}

  bool VisitCallExpr(CallExpr *CE) {
    if (const FunctionDecl *Callee = CE->getDirectCallee()) {
      if (knighter::declIsRole(Callee, "size_calculator"))
        SizeCalls.push_back(CE);
      else if (knighter::declIsRole(Callee, "reallocator"))
        ReallocCalls.push_back(CE);
    }
    return true;
  }
};

//===----------------------------------------------------------------------===//
// Checker class
//===----------------------------------------------------------------------===//

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "NULL dereference before reallocation",
                       "Memory error")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  SmallVector<const CallExpr *, 8> SizeCalls;
  SmallVector<const CallExpr *, 8> ReallocCalls;

  CallCollector Collector(SizeCalls, ReallocCalls);
  Collector.TraverseStmt(const_cast<Stmt *>(Body));

  if (SizeCalls.empty() || ReallocCalls.empty())
    return;

  ASTContext &Ctx = Mgr.getASTContext();

  for (const CallExpr *SizeCall : SizeCalls) {
    SmallVector<const ParmVarDecl *, 4> Params;
    SmallVector<const Expr *, 4> DerefExprs;

    for (unsigned i = 0; i < SizeCall->getNumArgs(); ++i) {
      collectDereferencedParams(SizeCall->getArg(i), FD, Params, DerefExprs);
    }

    for (size_t i = 0; i < Params.size(); ++i) {
      const ParmVarDecl *P = Params[i];
      const Expr *Deref = DerefExprs[i];

      if (isNullCheckedBefore(P, SizeCall, FD, Ctx))
        continue;

      if (!isSizeUsedByReallocator(SizeCall, ReallocCalls, FD, Ctx))
        continue;

      if (BT) {
        PathDiagnosticLocation Loc(Deref->getBeginLoc(),
                                   Ctx.getSourceManager());
        auto Report = std::make_unique<BasicBugReport>(
            *BT, "Pointer argument may be NULL when computing reallocation size",
            Loc);
        Report->addRange(Deref->getSourceRange());
        BR.emitReport(std::move(Report));
      }
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects NULL dereference before reallocation",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "size_calculator": {
    "names": ["xmlGrowCapacity"],
    "description": "Computes a size or capacity value from an input. Its result is often used as an allocation/reallocation size. It may dereference a pointer argument, so that argument must be NULL-checked before this call."
  },
  "reallocator": {
    "names": ["xmlRealloc"],
    "description": "Reallocates memory. Takes a pointer and a size, may return NULL on failure. The size must not be computed from a NULL-dereferenced pointer."
  }
}
*/
