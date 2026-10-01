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
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/ExprCXX.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

// Track the symbolic values returned by Regexp::Simplify() that have not yet
// been checked for NULL. No alias map is required for the target pattern.
REGISTER_SET_WITH_PROGRAMSTATE(UncheckedSimplifySet, SymbolRef)

namespace {

class SimplifyBodyVisitor : public RecursiveASTVisitor<SimplifyBodyVisitor> {
public:
  struct WalkCallInfo {
    const CXXMemberCallExpr *Call;
    const ValueDecl *ObjDecl;
    SourceLocation Loc;
  };

  struct StoppedCallInfo {
    const ValueDecl *ObjDecl;
    SourceLocation Loc;
  };

  llvm::SmallVector<WalkCallInfo, 4> WalkCalls;
  llvm::SmallVector<StoppedCallInfo, 4> StoppedCalls;

  bool VisitCXXMemberCallExpr(CXXMemberCallExpr *MCE) {
    const CXXMethodDecl *MD = MCE->getMethodDecl();
    if (!MD)
      return true;

    StringRef Name = MD->getName();
    const Expr *Obj = MCE->getImplicitObjectArgument();
    const ValueDecl *ObjDecl = getObjectDecl(Obj);

    if (Name == "Walk") {
      WalkCalls.push_back({MCE, ObjDecl, MCE->getBeginLoc()});
    } else if (Name == "stopped_early") {
      StoppedCalls.push_back({ObjDecl, MCE->getBeginLoc()});
    }

    return true;
  }

private:
  static const ValueDecl *getObjectDecl(const Expr *E) {
    if (!E)
      return nullptr;

    E = E->IgnoreParenImpCasts();

    if (const auto *DRE = dyn_cast<DeclRefExpr>(E))
      return DRE->getDecl();

    if (const auto *ME = dyn_cast<MemberExpr>(E))
      return ME->getMemberDecl();

    return nullptr;
  }
};

class SAGenTestChecker
    : public Checker<check::PostCall,
                     check::PreCall,
                     check::BranchCondition,
                     check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BTUse;
  mutable std::unique_ptr<BugType> BTMissing;

public:
  SAGenTestChecker()
      : BTUse(new BugType(this,
                          "Simplify() result used without NULL check",
                          "Null Pointer")),
        BTMissing(new BugType(this,
                              "Missing stopped_early() check after Walk()",
                              "Logic Error")) {}

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

private:
  bool isRegexpSimplifyCall(const CallEvent &Call) const;
  void reportUncheckedUse(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

bool SAGenTestChecker::isRegexpSimplifyCall(const CallEvent &Call) const {
  const auto *MCE = dyn_cast_or_null<CXXMemberCallExpr>(Call.getOriginExpr());
  if (!MCE)
    return false;

  const CXXMethodDecl *MD = MCE->getMethodDecl();
  if (!MD || MD->getName() != "Simplify")
    return false;

  const CXXRecordDecl *RD = MD->getParent();
  if (!RD)
    return false;

  return RD->getName() == "Regexp";
}

void SAGenTestChecker::checkPostCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  if (!isRegexpSimplifyCall(Call))
    return;

  ProgramStateRef State = C.getState();
  SVal RetVal = Call.getReturnValue();
  SymbolRef Sym = RetVal.getAsSymbol();

  if (Sym) {
    State = State->add<UncheckedSimplifySet>(Sym);
    C.addTransition(State);
  }
}

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) {
    C.addTransition(State);
    return;
  }

  CondE = CondE->IgnoreParenCasts();

  auto MarkChecked = [&](const Expr *E) {
    if (!E)
      return;

    SVal V = State->getSVal(E, C.getLocationContext());
    SymbolRef Sym = V.getAsSymbol();
    if (Sym && State->contains<UncheckedSimplifySet>(Sym)) {
      State = State->remove<UncheckedSimplifySet>(Sym);
    }
  };

  if (const auto *UO = dyn_cast<UnaryOperator>(CondE)) {
    if (UO->getOpcode() == UO_LNot) {
      MarkChecked(UO->getSubExpr()->IgnoreParenCasts());
    }
  } else if (const auto *BO = dyn_cast<BinaryOperator>(CondE)) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op == BO_EQ || Op == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

      bool LHSIsNull = LHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);
      bool RHSIsNull = RHS->isNullPointerConstant(
          C.getASTContext(), Expr::NPC_ValueDependentIsNull);

      if (LHSIsNull && !RHSIsNull) {
        MarkChecked(RHS);
      } else if (RHSIsNull && !LHSIsNull) {
        MarkChecked(LHS);
      }
    }
  } else {
    // Handles "if (ptr)" and similar implicit null checks.
    MarkChecked(CondE);
  }

  C.addTransition(State);
}

void SAGenTestChecker::reportUncheckedUse(const CallEvent &Call,
                                          CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BTUse, "Simplify() result used without NULL check", N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Any member call on the unchecked Simplify() result dereferences it,
  // e.g. simple->Decref().
  if (const auto *MCE =
          dyn_cast_or_null<CXXMemberCallExpr>(Call.getOriginExpr())) {
    const Expr *Obj = MCE->getImplicitObjectArgument();
    if (Obj) {
      SVal ObjVal = State->getSVal(Obj, C.getLocationContext());
      SymbolRef Sym = ObjVal.getAsSymbol();
      if (Sym && State->contains<UncheckedSimplifySet>(Sym)) {
        reportUncheckedUse(Call, C);
        return;
      }
    }
  }

  // BuildInfo(simple) is known to dereference its first argument.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (OriginExpr && ExprHasName(OriginExpr, "BuildInfo", C)) {
    if (Call.getNumArgs() > 0) {
      SVal Arg0 = Call.getArgSVal(0);
      SymbolRef Sym = Arg0.getAsSymbol();
      if (Sym && State->contains<UncheckedSimplifySet>(Sym)) {
        reportUncheckedUse(Call, C);
      }
    }
  }
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const auto *MD = dyn_cast<CXXMethodDecl>(D);
  if (!MD || MD->getName() != "Simplify")
    return;

  const CXXRecordDecl *RD = MD->getParent();
  if (!RD || RD->getName() != "Regexp")
    return;

  const Stmt *Body = MD->getBody();
  if (!Body)
    return;

  SimplifyBodyVisitor Visitor;
  Visitor.TraverseStmt(const_cast<Stmt *>(Body));

  const SourceManager &SM = Mgr.getASTContext().getSourceManager();

  for (const auto &W : Visitor.WalkCalls) {
    bool Found = false;

    for (const auto &S : Visitor.StoppedCalls) {
      if (W.ObjDecl && S.ObjDecl && W.ObjDecl == S.ObjDecl &&
          SM.isBeforeInTranslationUnit(W.Loc, S.Loc)) {
        Found = true;
        break;
      }
    }

    if (!Found) {
      auto Report = std::make_unique<BasicBugReport>(
          *BTMissing, "Missing stopped_early() check after Walk()",
          PathDiagnosticLocation::createBegin(W.Call, SM, nullptr));
      BR.emitReport(std::move(Report));
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing stopped_early() checks after Walk() and unchecked "
      "Regexp::Simplify() results",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
