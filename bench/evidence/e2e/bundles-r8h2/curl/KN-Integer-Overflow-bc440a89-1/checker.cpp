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
#include "clang/AST/Decl.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"

#include <string>
#include <cctype>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// ---------------------------------------------------------------------------
// Source-text helpers (we do not have a CheckerContext here).
// ---------------------------------------------------------------------------
static std::string getStmtSourceText(const Stmt *S, const SourceManager &SM,
                                     const LangOptions &LangOpts) {
  if (!S)
    return std::string();
  CharSourceRange Range = CharSourceRange::getTokenRange(S->getSourceRange());
  return Lexer::getSourceText(Range, SM, LangOpts).str();
}

static std::string stripWhitespace(StringRef S) {
  std::string Out;
  Out.reserve(S.size());
  for (char c : S) {
    if (!std::isspace(static_cast<unsigned char>(c)))
      Out.push_back(c);
  }
  return Out;
}

// ---------------------------------------------------------------------------
// Sub-tree search: does this Stmt carry an "input length" value?
// ---------------------------------------------------------------------------
class InputLengthFinder : public RecursiveASTVisitor<InputLengthFinder> {
  const llvm::SmallPtrSetImpl<const VarDecl *> &Vars;
  bool Found = false;

public:
  explicit InputLengthFinder(const llvm::SmallPtrSetImpl<const VarDecl *> &V)
      : Vars(V) {}

  bool found() const { return Found; }

  bool VisitMemberExpr(const MemberExpr *ME) {
    if (const ValueDecl *VD = ME->getMemberDecl()) {
      if (knighter::isRole("input_length", VD->getName()))
        Found = true;
    }
    return !Found;
  }

  bool VisitDeclRefExpr(const DeclRefExpr *DRE) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (Vars.count(VD))
        Found = true;
    }
    return !Found;
  }
};

static bool containsInputLength(
    const Stmt *S, const llvm::SmallPtrSetImpl<const VarDecl *> &Vars) {
  if (!S)
    return false;
  InputLengthFinder F(Vars);
  F.TraverseStmt(const_cast<Stmt *>(S));
  return F.found();
}

// ---------------------------------------------------------------------------
// First-pass collector: gathers all relevant AST nodes.
// ---------------------------------------------------------------------------
class Collector : public RecursiveASTVisitor<Collector> {
public:
  llvm::SmallVector<const VarDecl *, 8> VarsWithInit;
  llvm::SmallVector<const BinaryOperator *, 32> BinOps;
  llvm::SmallVector<const IfStmt *, 8> IfStmts;

  bool VisitVarDecl(const VarDecl *VD) {
    if (VD->hasInit())
      VarsWithInit.push_back(VD);
    return true;
  }

  bool VisitBinaryOperator(const BinaryOperator *BO) {
    BinOps.push_back(BO);
    return true;
  }

  bool VisitIfStmt(const IfStmt *IS) {
    IfStmts.push_back(IS);
    return true;
  }
};

// ---------------------------------------------------------------------------
// Guard helpers.
// ---------------------------------------------------------------------------
static bool thenBranchReturnsSentinel(const IfStmt *IS, const SourceManager &SM,
                                      const LangOptions &LangOpts) {
  const Stmt *Then = IS->getThen();
  if (!Then)
    return false;

  class Finder : public RecursiveASTVisitor<Finder> {
    const SourceManager &SM;
    const LangOptions &LangOpts;
    bool Found = false;

  public:
    Finder(const SourceManager &SM, const LangOptions &LO)
        : SM(SM), LangOpts(LO) {}

    bool found() const { return Found; }

    bool VisitReturnStmt(const ReturnStmt *RS) {
      const Expr *E = RS->getRetValue();
      if (E) {
        std::string Text =
            stripWhitespace(getStmtSourceText(E, SM, LangOpts));
        for (const std::string &N : knighter::roleNames("error_sentinel")) {
          if (!Text.empty() && Text == stripWhitespace(N)) {
            Found = true;
            break;
          }
        }
      }
      return !Found;
    }
  };

  Finder F(SM, LangOpts);
  F.TraverseStmt(const_cast<Stmt *>(Then));
  return F.found();
}

static bool conditionMentionsMaxInputSize(const Stmt *Cond,
                                          const SourceManager &SM,
                                          const LangOptions &LangOpts) {
  std::string Text = getStmtSourceText(Cond, SM, LangOpts);
  if (Text.empty())
    return false;
  for (const std::string &N : knighter::roleNames("max_input_size")) {
    if (!N.empty() && Text.find(N) != std::string::npos)
      return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Checker.
// ---------------------------------------------------------------------------
class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow",
                       "Potential integer overflow in encoded size "
                       "calculation")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  if (!knighter::isRole("encoded_size_calculator", FD->getName()))
    return;

  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  const SourceManager &SM = Mgr.getSourceManager();
  const LangOptions &LangOpts = Mgr.getLangOpts();

  // ---- Pass 1: collect all relevant nodes. --------------------------------
  Collector Col;
  Col.TraverseStmt(const_cast<Stmt *>(Body));

  // ---- Compute closure of variables carrying input length. ----------------
  llvm::SmallPtrSet<const VarDecl *, 8> InputLengthVars;
  bool Changed = true;
  while (Changed) {
    Changed = false;

    // VarDecls whose initializer mentions an input-length value.
    for (const VarDecl *VD : Col.VarsWithInit) {
      if (InputLengthVars.count(VD))
        continue;
      if (containsInputLength(VD->getInit(), InputLengthVars)) {
        InputLengthVars.insert(VD);
        Changed = true;
      }
    }

    // Assignments of input-length expressions to variables.
    for (const BinaryOperator *BO : Col.BinOps) {
      if (BO->getOpcode() != BO_Assign)
        continue;

      const VarDecl *LHSVar = nullptr;
      if (const DeclRefExpr *DRE =
              dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts()))
        LHSVar = dyn_cast<VarDecl>(DRE->getDecl());

      if (!LHSVar || InputLengthVars.count(LHSVar))
        continue;
      if (containsInputLength(BO->getRHS(), InputLengthVars)) {
        InputLengthVars.insert(LHSVar);
        Changed = true;
      }
    }
  }

  // ---- Pass 2: collect overflow-prone expressions. ------------------------
  llvm::SmallVector<const BinaryOperator *, 8> Candidates;
  for (const BinaryOperator *BO : Col.BinOps) {
    BinaryOperator::Opcode Op = BO->getOpcode();
    if (Op != BO_Mul && Op != BO_Add)
      continue;
    if (containsInputLength(BO->getLHS(), InputLengthVars) ||
        containsInputLength(BO->getRHS(), InputLengthVars)) {
      Candidates.push_back(BO);
    }
  }
  if (Candidates.empty())
    return;

  // ---- Collect overflow guards. -------------------------------------------
  llvm::SmallVector<const IfStmt *, 8> Guards;
  for (const IfStmt *IS : Col.IfStmts) {
    const Stmt *Cond = IS->getCond();
    if (!Cond)
      continue;
    if (!containsInputLength(Cond, InputLengthVars))
      continue;
    if (!conditionMentionsMaxInputSize(Cond, SM, LangOpts))
      continue;
    if (!thenBranchReturnsSentinel(IS, SM, LangOpts))
      continue;
    Guards.push_back(IS);
  }

  // ---- Decide and report (first unguarded candidate). ---------------------
  for (const BinaryOperator *BO : Candidates) {
    bool Guarded = false;
    for (const IfStmt *IS : Guards) {
      if (SM.isBeforeInTranslationUnit(IS->getBeginLoc(), BO->getBeginLoc())) {
        Guarded = true;
        break;
      }
    }
    if (Guarded)
      continue;

    PathDiagnosticLocation Loc =
        PathDiagnosticLocation::createBegin(BO, SM, nullptr);
    auto Report = std::make_unique<BasicBugReport>(
        *BT, "Potential integer overflow in encoded size calculation", Loc);
    Report->addRange(BO->getSourceRange());
    BR.emitReport(std::move(Report));
    break;
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects integer overflow in encoded size calculation without a guard",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "encoded_size_calculator": {
    "names": ["encoder_base64_size"],
    "description": "function that computes an encoded output size from an input length; it must guard against signed integer overflow before doing arithmetic"
  },
  "input_length": {
    "names": ["datasize"],
    "description": "field or variable holding the length of input data to be encoded, whose value may be arbitrarily large"
  },
  "max_input_size": {
    "names": ["BASE64_MAX_INPUT_SIZE"],
    "description": "macro or constant defining the maximum input length that can safely participate in encoded-size arithmetic without overflow"
  },
  "error_sentinel": {
    "names": ["-1"],
    "description": "sentinel return value used by a size calculator to signal an error or overflow condition"
  }
}
*/
