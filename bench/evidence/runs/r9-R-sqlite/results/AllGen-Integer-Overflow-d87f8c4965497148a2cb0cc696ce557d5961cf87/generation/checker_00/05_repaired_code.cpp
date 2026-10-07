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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/DenseMap.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

#include <memory>
#include <string>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_MAP_WITH_PROGRAMSTATE(UnclampedLenMap, const MemRegion *, bool)

namespace {

static const VarDecl *getAssignedVarDecl(const Stmt *S) {
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (const auto *DRE = dyn_cast<DeclRefExpr>(LHS))
        return dyn_cast<VarDecl>(DRE->getDecl());
    }
  } else if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    if (DS->isSingleDecl()) {
      if (const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl()))
        return VD;
    }
  }
  return nullptr;
}

static const Expr *getAssignedRHS(const Stmt *S) {
  if (const auto *BO = dyn_cast<BinaryOperator>(S)) {
    if (BO->getOpcode() == BO_Assign)
      return BO->getRHS();
  } else if (const auto *DS = dyn_cast<DeclStmt>(S)) {
    if (DS->isSingleDecl()) {
      if (const auto *VD = dyn_cast<VarDecl>(DS->getSingleDecl()))
        return VD->getInit();
    }
  }
  return nullptr;
}

static bool isPointerDifference(const BinaryOperator *BO) {
  return BO && BO->getOpcode() == BO_Sub &&
         BO->getLHS()->getType()->isPointerType() &&
         BO->getRHS()->getType()->isPointerType();
}

class SAGenTestChecker : public Checker<check::Bind, check::PreCall> {
  mutable std::unique_ptr<BugType> BT;
  mutable llvm::DenseMap<const FunctionDecl *, bool> UsesUtf8ScannerCache;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Unchecked narrowing of pointer difference",
                       "Integer overflow")) {}

  void checkBind(SVal Loc, SVal, const Stmt *S, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  bool functionUsesUtf8Scanner(const FunctionDecl *FD, CheckerContext &C) const;
  void reportBug(const CallEvent &Call, const Expr *ArgE,
                 CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBind(SVal Loc, SVal, const Stmt *S,
                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;
  MR = MR->getBaseRegion();
  if (!MR)
    return;

  const VarDecl *VD = getAssignedVarDecl(S);
  if (!VD) {
    State = State->remove<UnclampedLenMap>(MR);
    C.addTransition(State);
    return;
  }

  QualType VarTy = VD->getType();
  if (!VarTy->isIntegerType() ||
      C.getASTContext().getTypeSize(VarTy) > 32) {
    State = State->remove<UnclampedLenMap>(MR);
    C.addTransition(State);
    return;
  }

  const Expr *RHS = getAssignedRHS(S);
  if (!RHS) {
    State = State->remove<UnclampedLenMap>(MR);
    C.addTransition(State);
    return;
  }

  const Expr *NoParen = RHS->IgnoreParens();
  const auto *CE = dyn_cast<CastExpr>(NoParen);
  if (!CE) {
    State = State->remove<UnclampedLenMap>(MR);
    C.addTransition(State);
    return;
  }

  QualType CastTy = CE->getType();
  if (!CastTy->isSignedIntegerType() ||
      C.getASTContext().getTypeSize(CastTy) != 32) {
    State = State->remove<UnclampedLenMap>(MR);
    C.addTransition(State);
    return;
  }

  const Expr *Sub = CE->getSubExpr()->IgnoreParenImpCasts();
  const auto *BO = dyn_cast<BinaryOperator>(Sub);
  if (!isPointerDifference(BO)) {
    State = State->remove<UnclampedLenMap>(MR);
    C.addTransition(State);
    return;
  }

  for (const std::string &Name : knighter::roleNames("clamp")) {
    if (ExprHasName(CE, Name, C)) {
      State = State->remove<UnclampedLenMap>(MR);
      C.addTransition(State);
      return;
    }
  }

  const Decl *D = C.getLocationContext()->getDecl();
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(D);
  if (!FD || !functionUsesUtf8Scanner(FD, C)) {
    State = State->remove<UnclampedLenMap>(MR);
    C.addTransition(State);
    return;
  }

  State = State->set<UnclampedLenMap>(MR, true);
  C.addTransition(State);
}

bool SAGenTestChecker::functionUsesUtf8Scanner(const FunctionDecl *FD,
                                               CheckerContext &C) const {
  if (!FD)
    return false;

  auto It = UsesUtf8ScannerCache.find(FD);
  if (It != UsesUtf8ScannerCache.end())
    return It->second;

  bool Result = false;
  if (const Stmt *Body = FD->getBody()) {
    const SourceManager &SM = C.getSourceManager();
    const LangOptions &LangOpts = C.getLangOpts();
    CharSourceRange Range =
        CharSourceRange::getTokenRange(Body->getSourceRange());
    if (Range.isValid()) {
      StringRef Text = Lexer::getSourceText(Range, SM, LangOpts);
      for (const std::string &Name : knighter::roleNames("utf8_scanner")) {
        if (Text.contains(Name)) {
          Result = true;
          break;
        }
      }
    }
  }

  UsesUtf8ScannerCache[FD] = Result;
  return Result;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  if (!knighter::callIsRole(Call, "buffer_copy"))
    return;

  ProgramStateRef State = C.getState();
  for (unsigned I = 0; I < Call.getNumArgs(); ++I) {
    const Expr *ArgE = Call.getArgExpr(I);
    if (!ArgE)
      continue;

    ArgE = ArgE->IgnoreParenImpCasts();
    const auto *DRE = dyn_cast<DeclRefExpr>(ArgE);
    if (!DRE)
      continue;

    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      continue;

    SVal L = State->getLValue(VD, C.getLocationContext());
    const MemRegion *MR = L.getAsRegion();
    if (!MR)
      continue;

    MR = MR->getBaseRegion();
    if (!MR)
      continue;

    const bool *Unclamped = State->get<UnclampedLenMap>(MR);
    if (Unclamped && *Unclamped) {
      reportBug(Call, ArgE, C);
      return;
    }
  }
}

void SAGenTestChecker::reportBug(const CallEvent &Call, const Expr *ArgE,
                                 CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      *BT,
      "Unchecked narrowing of pointer difference used as buffer copy length",
      N);
  R->addRange(ArgE->getSourceRange());
  C.emitReport(std::move(R));
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unchecked narrowing of pointer differences before buffer copies",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "utf8_scanner": {
    "names": ["SQLITE_SKIP_UTF8"],
    "description": "macro/function that advances a byte pointer past one encoded character, consuming up to several bytes per call"
  },
  "buffer_copy": {
    "names": ["sqlite3_str_append"],
    "description": "appends a buffer of a computed length to an output accumulator"
  },
  "clamp": {
    "names": ["MIN"],
    "description": "returns the smaller of two values; used to cap a computed length before narrowing to int"
  }
}
*/
