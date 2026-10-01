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

#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/ADT/SmallVector.h"
#include <algorithm>
#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

struct ShiftInfo {
  const BinaryOperator *Shift = nullptr;
  std::string CountName;
  llvm::SmallVector<std::string, 2> LeadNames;
};

class Utf8ShiftVisitor : public RecursiveASTVisitor<Utf8ShiftVisitor> {
  ASTContext &AC;

public:
  llvm::SmallVector<ShiftInfo, 4> Shifts;
  llvm::SmallVector<const IfStmt *, 8> Ifs;

  explicit Utf8ShiftVisitor(ASTContext &AC) : AC(AC) {}

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Shl)
      return true;

    const Expr *RHS = BO->getRHS();
    std::string CountName;
    if (!matchCountTimesFive(RHS, CountName))
      return true;

    ShiftInfo Info;
    Info.Shift = BO;
    Info.CountName = CountName;
    collectDeclRefNames(BO->getLHS(), Info.LeadNames);
    Shifts.push_back(Info);
    return true;
  }

  bool VisitIfStmt(IfStmt *IS) {
    Ifs.push_back(IS);
    return true;
  }

  bool hasGuardBefore(const ShiftInfo &Info) const {
    SourceManager &SM = AC.getSourceManager();
    for (const IfStmt *IS : Ifs) {
      if (!IS->getCond() || !IS->getThen())
        continue;
      if (!SM.isBeforeInTranslationUnit(IS->getBeginLoc(),
                                        Info.Shift->getBeginLoc()))
        continue;
      if (!conditionGuards(IS->getCond(), Info))
        continue;
      if (thenReturnsNull(IS->getThen(), AC))
        return true;
    }
    return false;
  }

private:
  static bool isDeclRef(const Expr *E, std::string &Name) {
    E = E->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const auto *ND = dyn_cast<NamedDecl>(DRE->getDecl())) {
        Name = ND->getNameAsString();
        return true;
      }
    }
    return false;
  }

  static bool isIntLiteral(const Expr *E, int64_t Val) {
    E = E->IgnoreParenImpCasts();
    if (const auto *IL = dyn_cast<IntegerLiteral>(E))
      return IL->getValue().getSExtValue() == Val;
    return false;
  }

  static bool matchCountTimesFive(const Expr *E, std::string &CountName) {
    E = E->IgnoreParenImpCasts();
    const auto *BO = dyn_cast<BinaryOperator>(E);
    if (!BO || BO->getOpcode() != BO_Mul)
      return false;

    const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
    const Expr *R = BO->getRHS()->IgnoreParenImpCasts();

    if (isDeclRef(L, CountName) && isIntLiteral(R, 5))
      return true;
    if (isDeclRef(R, CountName) && isIntLiteral(L, 5))
      return true;
    return false;
  }

  static void collectDeclRefNames(const Expr *E,
                                  llvm::SmallVectorImpl<std::string> &Names) {
    if (!E)
      return;
    E = E->IgnoreParenImpCasts();
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const auto *ND = dyn_cast<NamedDecl>(DRE->getDecl())) {
        std::string Name = ND->getNameAsString();
        if (std::find(Names.begin(), Names.end(), Name) == Names.end())
          Names.push_back(Name);
      }
      return;
    }
    for (const Stmt *Child : E->children()) {
      if (const auto *ChildExpr = dyn_cast<Expr>(Child))
        collectDeclRefNames(ChildExpr, Names);
    }
  }

  static bool matchesGuard(const std::string &VarName,
                           BinaryOperator::Opcode Op, int64_t Val, bool VarLeft,
                           const ShiftInfo &Info) {
    if (VarName == Info.CountName) {
      if (VarLeft) {
        if ((Op == BO_GT && Val >= 5) || (Op == BO_GE && Val >= 6))
          return true;
      } else {
        if ((Op == BO_LT && Val >= 5) || (Op == BO_LE && Val >= 6))
          return true;
      }
    }

    for (const std::string &LeadName : Info.LeadNames) {
      if (VarName == LeadName) {
        if (VarLeft) {
          if ((Op == BO_GE && Val >= 0xfe) || (Op == BO_GT && Val >= 0xfd))
            return true;
        } else {
          if ((Op == BO_LE && Val >= 0xfe) || (Op == BO_LT && Val >= 0xfd))
            return true;
        }
      }
    }
    return false;
  }

  static bool conditionGuards(const Expr *Cond, const ShiftInfo &Info) {
    Cond = Cond->IgnoreParenImpCasts();

    if (const auto *BO = dyn_cast<BinaryOperator>(Cond)) {
      if (BO->getOpcode() == BO_LOr)
        return conditionGuards(BO->getLHS(), Info) ||
               conditionGuards(BO->getRHS(), Info);

      if (BO->getOpcode() != BO_GE && BO->getOpcode() != BO_GT &&
          BO->getOpcode() != BO_LE && BO->getOpcode() != BO_LT)
        return false;

      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      std::string VarName;
      int64_t Val = 0;

      if (isDeclRef(L, VarName) && isIntLiteral(R, Val))
        return matchesGuard(VarName, BO->getOpcode(), Val, true, Info);
      if (isIntLiteral(L, Val) && isDeclRef(R, VarName))
        return matchesGuard(VarName, BO->getOpcode(), Val, false, Info);
    }
    return false;
  }

  static bool isNullReturn(const ReturnStmt *RS, ASTContext &AC) {
    if (!RS)
      return false;
    const Expr *Ret = RS->getRetValue();
    if (!Ret)
      return false;
    if (Ret->isNullPointerConstant(AC, Expr::NPC_ValueDependentIsNull))
      return true;
    if (const auto *IL = dyn_cast<IntegerLiteral>(Ret->IgnoreParenImpCasts()))
      return IL->getValue().isZero();
    return false;
  }

  static bool thenReturnsNull(const Stmt *S, ASTContext &AC) {
    if (!S)
      return false;
    if (const auto *RS = dyn_cast<ReturnStmt>(S))
      return isNullReturn(RS, AC);
    for (const Stmt *Child : S->children()) {
      if (thenReturnsNull(Child, AC))
        return true;
    }
    return false;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unsafe shift in UTF-8 decode",
                       "Undefined Behavior")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const auto *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || FD->getNameAsString() != "utf8_decode")
    return;

  ASTContext &AC = Mgr.getASTContext();
  Utf8ShiftVisitor Visitor(AC);
  Visitor.TraverseStmt(FD->getBody());

  for (const ShiftInfo &Info : Visitor.Shifts) {
    if (!Info.Shift)
      continue;
    if (Visitor.hasGuardBefore(Info))
      continue;

    PathDiagnosticLocation Loc(Info.Shift->getBeginLoc(),
                               AC.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, "Unsafe shift in UTF-8 decode: leading byte not validated", Loc);
    Report->addRange(Info.Shift->getSourceRange());
    BR.emitReport(std::move(Report));
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsafe shift in utf8_decode due to unvalidated leading byte",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
