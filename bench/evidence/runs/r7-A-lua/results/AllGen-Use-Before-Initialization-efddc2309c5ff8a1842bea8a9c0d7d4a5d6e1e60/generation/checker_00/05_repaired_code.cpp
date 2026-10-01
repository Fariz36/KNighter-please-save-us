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

#include "clang/AST/Expr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

class MatchdepthVisitor : public RecursiveASTVisitor<MatchdepthVisitor> {
  using Base = RecursiveASTVisitor<MatchdepthVisitor>;

public:
  bool SimpleAssignToMatchdepth = false;
  bool ModifyMatchdepth = false;
  bool CallLuaLError = false;
  bool CallReprepstate = false;
  bool ReprepstateInLoop = false;
  bool UpvalueAccess = false;
  int LoopDepth = 0;

  bool isMatchdepthMember(const Expr *E) {
    if (!E)
      return false;
    E = E->IgnoreParenImpCasts();
    const auto *ME = dyn_cast<MemberExpr>(E);
    if (!ME)
      return false;
    const ValueDecl *VD = ME->getMemberDecl();
    return VD && VD->getName() == "matchdepth";
  }

  void checkAssignment(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_Assign && isMatchdepthMember(BO->getLHS()))
      SimpleAssignToMatchdepth = true;
    if (BO->isAssignmentOp() && isMatchdepthMember(BO->getLHS()))
      ModifyMatchdepth = true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    checkAssignment(BO);
    return true;
  }

  bool VisitCompoundAssignOperator(CompoundAssignOperator *CAO) {
    checkAssignment(CAO);
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (UO->isIncrementDecrementOp() && isMatchdepthMember(UO->getSubExpr()))
      ModifyMatchdepth = true;
    return true;
  }

  bool VisitCallExpr(CallExpr *CE) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      StringRef Name = FD->getName();
      if (Name == "luaL_error") {
        CallLuaLError = true;
      } else if (Name == "reprepstate") {
        CallReprepstate = true;
        if (LoopDepth > 0)
          ReprepstateInLoop = true;
      } else if (Name == "lua_touserdata") {
        UpvalueAccess = true;
      }
    }
    return true;
  }

  bool TraverseForStmt(ForStmt *S) {
    ++LoopDepth;
    bool res = Base::TraverseForStmt(S);
    --LoopDepth;
    return res;
  }

  bool TraverseWhileStmt(WhileStmt *S) {
    ++LoopDepth;
    bool res = Base::TraverseWhileStmt(S);
    --LoopDepth;
    return res;
  }

  bool TraverseDoStmt(DoStmt *S) {
    ++LoopDepth;
    bool res = Base::TraverseDoStmt(S);
    --LoopDepth;
    return res;
  }
};

class SAGenTestChecker
    : public Checker<check::ASTCodeBody, check::EndAnalysis> {
  mutable std::unique_ptr<BugType> BT;

  mutable bool PrepstateResetsMatchdepth = false;
  mutable bool MatchModifiesMatchdepth = false;
  mutable bool MatchCallsLuaLError = false;
  mutable bool ReprepstateMissingMatchdepth = false;
  mutable bool GmatchReusesState = false;
  mutable const FunctionDecl *ReprepstateFD = nullptr;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Lua gmatch matchdepth reset", "Logic Error")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                        ExprEngine &Eng) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  StringRef FnName = FD->getName();

  MatchdepthVisitor V;
  V.TraverseStmt(Body);

  if (FnName == "prepstate") {
    if (V.SimpleAssignToMatchdepth)
      PrepstateResetsMatchdepth = true;
  } else if (FnName == "match") {
    if (V.ModifyMatchdepth)
      MatchModifiesMatchdepth = true;
    if (V.CallLuaLError)
      MatchCallsLuaLError = true;
  } else if (FnName == "reprepstate") {
    if (!V.SimpleAssignToMatchdepth) {
      ReprepstateMissingMatchdepth = true;
      ReprepstateFD = FD;
    }
  } else if (FnName == "gmatch_aux") {
    if (V.ReprepstateInLoop && V.UpvalueAccess)
      GmatchReusesState = true;
  }
}

void SAGenTestChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                                        ExprEngine &Eng) const {
  if (PrepstateResetsMatchdepth && MatchModifiesMatchdepth &&
      MatchCallsLuaLError && ReprepstateMissingMatchdepth &&
      GmatchReusesState && ReprepstateFD) {
    auto Report = std::make_unique<BasicBugReport>(
        *BT,
        "matchdepth not reset in reprepstate; stale value after error can "
        "break recursion guard",
        PathDiagnosticLocation::create(ReprepstateFD, BR.getSourceManager()));
    BR.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing matchdepth reset in Lua gmatch iterator",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
