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
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

#include <algorithm>
#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// -------------------------------------------------------------------------
// Data structures used to collect facts during AST traversal
// -------------------------------------------------------------------------

struct Assumption {
  const FieldDecl *Field;
  const Expr *AssertedExpr;
  std::string AssertedText;
  const Stmt *AssertStmt;
};

struct MissingReset {
  const FunctionDecl *PerUseInit;
  const FieldDecl *Field;
  const Expr *AssertedExpr;
  std::string AssertedText;
  const Stmt *AssertStmt;
};

struct Event {
  enum Kind { Write, Error } K;
  unsigned Offset;
  const FieldDecl *Field;
  const CallExpr *CE;
};

// -------------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------------

static std::string getExprText(const Expr *E, ASTContext &Ctx) {
  if (!E)
    return "";
  SourceManager &SM = Ctx.getSourceManager();
  const LangOptions &LangOpts = Ctx.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  return Lexer::getSourceText(Range, SM, LangOpts).str();
}

static bool exprHasName(const Expr *E, StringRef Name, ASTContext &Ctx) {
  if (!E)
    return false;
  SourceManager &SM = Ctx.getSourceManager();
  const LangOptions &LangOpts = Ctx.getLangOpts();
  CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
  StringRef ExprText = Lexer::getSourceText(Range, SM, LangOpts);
  return ExprText.contains(Name);
}

// -------------------------------------------------------------------------
// Visitor for `init` functions: collect assignments and aborting_assert
// assumptions.
// -------------------------------------------------------------------------

class InitCollector : public RecursiveASTVisitor<InitCollector> {
public:
  const FunctionDecl *FD;
  ASTContext &Ctx;
  llvm::DenseMap<const FieldDecl *, const Expr *> &Assignments;
  llvm::SmallVector<Assumption, 4> &Assumptions;

  InitCollector(const FunctionDecl *FD, ASTContext &Ctx,
                llvm::DenseMap<const FieldDecl *, const Expr *> &Assignments,
                llvm::SmallVector<Assumption, 4> &Assumptions)
      : FD(FD), Ctx(Ctx), Assignments(Assignments), Assumptions(Assumptions) {}

  bool isStateField(MemberExpr *ME) {
    Expr *Base = ME->getBase()->IgnoreParenImpCasts();
    if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base)) {
      if (ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(DRE->getDecl())) {
        if (dyn_cast<FunctionDecl>(PVD->getDeclContext()) == FD)
          return true;
      }
    }
    return false;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (!BO->isAssignmentOp())
      return true;
    Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
    if (MemberExpr *ME = dyn_cast<MemberExpr>(LHS)) {
      if (isStateField(ME)) {
        if (const FieldDecl *Field = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
          Assignments[Field] = BO->getRHS();
        }
      }
    }
    return true;
  }

  bool VisitExpr(Expr *E) {
    // Look for an aborting_assert invocation (possibly a macro expansion)
    for (const std::string &Name : knighter::roleNames("aborting_assert")) {
      if (exprHasName(E, Name, Ctx)) {
        Expr *Inner = E->IgnoreParenImpCasts();
        Expr *Cond = nullptr;
        if (CallExpr *CE = dyn_cast<CallExpr>(Inner)) {
          if (CE->getNumArgs() >= 1)
            Cond = CE->getArg(0);
        } else if (ConditionalOperator *CO = dyn_cast<ConditionalOperator>(Inner)) {
          Cond = CO->getCond();
        }
        if (Cond) {
          Cond = Cond->IgnoreParenImpCasts();
          if (BinaryOperator *BO = dyn_cast<BinaryOperator>(Cond)) {
            if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
              Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
              Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
              const FieldDecl *Field = nullptr;
              Expr *Other = nullptr;
              if (MemberExpr *ME = dyn_cast<MemberExpr>(LHS)) {
                if (isStateField(ME)) {
                  Field = dyn_cast<FieldDecl>(ME->getMemberDecl());
                  Other = RHS;
                }
              }
              if (!Field) {
                if (MemberExpr *ME = dyn_cast<MemberExpr>(RHS)) {
                  if (isStateField(ME)) {
                    Field = dyn_cast<FieldDecl>(ME->getMemberDecl());
                    Other = LHS;
                  }
                }
              }
              if (Field && Other) {
                Assumptions.push_back({Field, Other, getExprText(Other, Ctx), E});
              }
            }
          }
        }
        break; // only need one matching role name
      }
    }
    return true;
  }
};

// -------------------------------------------------------------------------
// Visitor for functions containing `error_setter`: collect writes to fields
// and error_setter calls in source order.
// -------------------------------------------------------------------------

class ErrorCollector : public RecursiveASTVisitor<ErrorCollector> {
public:
  ASTContext &Ctx;
  SourceManager &SM;
  llvm::SmallVector<Event, 16> &Events;

  ErrorCollector(ASTContext &Ctx, llvm::SmallVector<Event, 16> &Events)
      : Ctx(Ctx), SM(Ctx.getSourceManager()), Events(Events) {}

  unsigned getOffset(SourceLocation Loc) {
    if (Loc.isInvalid())
      return 0;
    SourceLocation ExpLoc = SM.getExpansionLoc(Loc);
    return SM.getFileOffset(ExpLoc);
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->isAssignmentOp()) {
      Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (MemberExpr *ME = dyn_cast<MemberExpr>(LHS)) {
        if (const FieldDecl *Field = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
          Events.push_back({Event::Write, getOffset(BO->getBeginLoc()), Field, nullptr});
        }
      }
    }
    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (UO->isIncrementDecrementOp()) {
      Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
      if (MemberExpr *ME = dyn_cast<MemberExpr>(Sub)) {
        if (const FieldDecl *Field = dyn_cast<FieldDecl>(ME->getMemberDecl())) {
          Events.push_back({Event::Write, getOffset(UO->getBeginLoc()), Field, nullptr});
        }
      }
    }
    return true;
  }

  bool VisitCallExpr(CallExpr *CE) {
    if (knighter::callExprIsRole(CE, "error_setter", Ctx)) {
      Events.push_back({Event::Error, getOffset(CE->getBeginLoc()), nullptr, CE});
    }
    return true;
  }
};

// -------------------------------------------------------------------------
// Main checker class
// -------------------------------------------------------------------------

class SAGenTestChecker : public Checker<check::ASTCodeBody, check::EndAnalysis> {
  mutable std::unique_ptr<BugType> BT;

  // SourceManager of the translation unit currently being analyzed. Kept so
  // that PathDiagnosticLocation objects can be constructed for reports during
  // checkEndAnalysis.
  mutable const SourceManager *SM = nullptr;

  // Facts collected during AST traversal
  mutable llvm::DenseMap<const FunctionDecl *,
                         llvm::DenseMap<const FieldDecl *, const Expr *>>
      InitAssignments;
  mutable llvm::DenseMap<const FieldDecl *,
                         llvm::SmallVector<std::pair<const FunctionDecl *, std::string>, 4>>
      AllInitAssignments;
  mutable llvm::SmallVector<MissingReset, 4> MissingResets;
  mutable llvm::DenseSet<const FieldDecl *> ErrorCorruptibleFields;

public:
  SAGenTestChecker()
      : BT(std::make_unique<BugType>(this, "Missing State Reset",
                                     "State Management")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                        ExprEngine &Eng) const;
};

} // end anonymous namespace

// -------------------------------------------------------------------------
// checkASTCodeBody implementation
// -------------------------------------------------------------------------

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;
  ASTContext &Ctx = Mgr.getASTContext();
  SM = &Ctx.getSourceManager();

  // 1) Collect facts from `init` functions
  if (knighter::declIsRole(FD, "init")) {
    llvm::DenseMap<const FieldDecl *, const Expr *> Assignments;
    llvm::SmallVector<Assumption, 4> Assumptions;
    InitCollector Collector(FD, Ctx, Assignments, Assumptions);
    Collector.TraverseStmt(FD->getBody());

    InitAssignments[FD] = Assignments;
    for (auto &Pair : Assignments) {
      std::string Text = getExprText(Pair.second, Ctx);
      AllInitAssignments[Pair.first].push_back({FD, Text});
    }

    for (auto &Ass : Assumptions) {
      if (Assignments.find(Ass.Field) == Assignments.end()) {
        MissingResets.push_back({FD, Ass.Field, Ass.AssertedExpr,
                                 Ass.AssertedText, Ass.AssertStmt});
      }
    }
  }

  // 2) Collect writes and error_setter calls to identify corruptible fields
  llvm::SmallVector<Event, 16> Events;
  ErrorCollector ErrCollector(Ctx, Events);
  ErrCollector.TraverseStmt(FD->getBody());

  bool HasError = false;
  for (auto &E : Events) {
    if (E.K == Event::Error) {
      HasError = true;
      break;
    }
  }
  if (HasError) {
    std::sort(Events.begin(), Events.end(),
              [](const Event &A, const Event &B) {
                return A.Offset < B.Offset;
              });
    llvm::DenseMap<const FieldDecl *, unsigned> LastWriteIndex;
    for (unsigned i = 0; i < Events.size(); ++i) {
      if (Events[i].K == Event::Write) {
        const FieldDecl *F = Events[i].Field;
        auto It = LastWriteIndex.find(F);
        if (It != LastWriteIndex.end()) {
          unsigned LastIdx = It->second;
          bool HasErrBetween = false;
          for (unsigned j = LastIdx + 1; j < i; ++j) {
            if (Events[j].K == Event::Error) {
              HasErrBetween = true;
              break;
            }
          }
          if (HasErrBetween) {
            ErrorCorruptibleFields.insert(F);
          }
        }
        LastWriteIndex[F] = i;
      }
    }
  }
}

// -------------------------------------------------------------------------
// checkEndAnalysis implementation
// -------------------------------------------------------------------------

void SAGenTestChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR,
                                        ExprEngine &Eng) const {
  if (!SM)
    return;

  for (auto &MR : MissingResets) {
    if (!ErrorCorruptibleFields.contains(MR.Field))
      continue;

    bool Found = false;
    auto It = AllInitAssignments.find(MR.Field);
    if (It != AllInitAssignments.end()) {
      for (auto &Pair : It->second) {
        if (Pair.first == MR.PerUseInit)
          continue;
        if (Pair.second == MR.AssertedText) {
          Found = true;
          break;
        }
      }
    }

    if (Found) {
      PathDiagnosticLocation L =
          PathDiagnosticLocation::createBegin(MR.AssertStmt, *SM, nullptr);
      auto Report = std::make_unique<BasicBugReport>(
          *BT,
          "state counter not reinitialized in per-use init; may be stale "
          "after error",
          L);
      BR.emitReport(std::move(Report));
    }
  }
}

// -------------------------------------------------------------------------
// Registration
// -------------------------------------------------------------------------

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing state counter reset in per-use init that can leave "
      "stale state after an error",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "init": {
    "names": ["prepstate", "reprepstate"],
    "description": "initializes or reinitializes a reusable state object; per-use init must reset all mutable fields that can be corrupted by an aborted operation"
  },
  "error_setter": {
    "names": ["luaL_error"],
    "description": "reports/raises an error and aborts the current operation without returning normally"
  },
  "aborting_assert": {
    "names": ["lua_assert"],
    "description": "macro that aborts execution when its condition is false"
  }
}
*/
