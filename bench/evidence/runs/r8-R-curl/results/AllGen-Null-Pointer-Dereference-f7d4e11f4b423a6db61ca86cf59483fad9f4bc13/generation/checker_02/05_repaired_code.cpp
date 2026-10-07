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
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper: check if two expressions refer to the same base.
static bool sameExpr(const Expr *A, const Expr *B, ASTContext &Ctx) {
  if (!A || !B) return false;
  A = A->IgnoreParenImpCasts();
  B = B->IgnoreParenImpCasts();
  if (const DeclRefExpr *DREA = dyn_cast<DeclRefExpr>(A))
    if (const DeclRefExpr *DREB = dyn_cast<DeclRefExpr>(B))
      return DREA->getDecl() == DREB->getDecl();
  // Fallback: compare source locations.
  SourceLocation LA = A->getBeginLoc();
  SourceLocation LB = B->getBeginLoc();
  if (LA.isInvalid() || LB.isInvalid()) return false;
  return LA == LB;
}

// Helper: find a MemberExpr accessing a field with the given role.
class FieldAccessFinder : public RecursiveASTVisitor<FieldAccessFinder> {
  StringRef Role;
  const Expr *Base = nullptr;
  bool Found = false;
public:
  FieldAccessFinder(StringRef R) : Role(R) {}
  bool VisitMemberExpr(MemberExpr *ME) {
    if (Found) return false;
    const ValueDecl *VD = ME->getMemberDecl();
    if (VD && knighter::declIsRole(VD, Role)) {
      Base = ME->getBase()->IgnoreParenImpCasts();
      Found = true;
      return false;
    }
    return true;
  }
  bool found() const { return Found; }
  const Expr *getBase() const { return Base; }
};

static bool containsFieldAccess(const Expr *E, StringRef Role, const Expr *&Base) {
  if (!E) return false;
  FieldAccessFinder Finder(Role);
  Finder.TraverseStmt(const_cast<Expr*>(E));
  if (Finder.found()) {
    Base = Finder.getBase();
    return true;
  }
  return false;
}

// Helper: check if a statement contains a return of an error code.
class ErrorReturnFinder : public RecursiveASTVisitor<ErrorReturnFinder> {
  bool Found = false;
public:
  bool VisitReturnStmt(ReturnStmt *RS) {
    if (Found) return false;
    const Expr *RetE = RS->getRetValue();
    if (RetE) {
      RetE = RetE->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(RetE)) {
        if (knighter::declIsRole(DRE->getDecl(), "error_return")) {
          Found = true;
          return false;
        }
      }
    }
    return true;
  }
  bool found() const { return Found; }
};

static bool hasErrorReturn(const Stmt *S) {
  if (!S) return false;
  ErrorReturnFinder Finder;
  Finder.TraverseStmt(const_cast<Stmt*>(S));
  return Finder.found();
}

// Helper: check if a call expression is a buffer copy operation.
static bool isBufferCopyCall(const CallExpr *CE) {
  if (!CE) return false;
  if (const FunctionDecl *FD = CE->getDirectCallee()) {
    if (knighter::isRole("buffer_copy", FD->getName())) return true;
  }
  const Expr *Callee = CE->getCallee();
  if (Callee) {
    Callee = Callee->IgnoreParenImpCasts();
    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Callee)) {
      if (const NamedDecl *ND = dyn_cast<NamedDecl>(DRE->getDecl())) {
        if (knighter::isRole("buffer_copy", ND->getName())) return true;
      }
    }
  }
  return false;
}

// Helper: check if an assignment is a whole-struct copy involving Base.
static bool isWholeStructCopy(const BinaryOperator *BO, const Expr *Base,
                              ASTContext &Ctx) {
  if (!BO || BO->getOpcode() != BO_Assign) return false;
  const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
  if (sameExpr(RHS, Base, Ctx)) return true;
  if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(RHS)) {
    if (UO->getOpcode() == UO_Deref) {
      if (sameExpr(UO->getSubExpr(), Base, Ctx)) return true;
    }
  }
  return false;
}

// Visitor to find vulnerable validation guards.
class GuardFinder : public RecursiveASTVisitor<GuardFinder> {
  ASTContext &Ctx;
public:
  struct Guard {
    const Expr *Base;
    SourceLocation Loc;
  };
  SmallVector<Guard, 4> Guards;
  GuardFinder(ASTContext &C) : Ctx(C) {}

  bool VisitIfStmt(IfStmt *IS) {
    if (!IS) return true;
    const Expr *Cond = IS->getCond();
    if (!Cond) return true;
    const Expr *LengthBase = nullptr;
    if (containsFieldAccess(Cond, "length_field", LengthBase)) {
      if (hasErrorReturn(IS->getThen())) {
        const Expr *DataBase = nullptr;
        bool ChecksData = containsFieldAccess(Cond, "data_pointer", DataBase);
        if (ChecksData && sameExpr(LengthBase, DataBase, Ctx)) {
          return true; // safe guard, already checks data pointer
        }
        Guards.push_back({LengthBase, IS->getIfLoc()});
      }
    }
    return true;
  }
};

// Visitor to find uses of the data pointer after a vulnerable guard.
class UseFinder : public RecursiveASTVisitor<UseFinder> {
  const Expr *Base;
  SourceLocation GuardLoc;
  ASTContext &Ctx;
  bool Found = false;

  bool isAfter(SourceLocation Loc) const {
    if (Loc.isInvalid() || GuardLoc.isInvalid()) return true;
    return Ctx.getSourceManager().isBeforeInTranslationUnit(GuardLoc, Loc);
  }

public:
  UseFinder(const Expr *B, SourceLocation L, ASTContext &C)
      : Base(B), GuardLoc(L), Ctx(C) {}

  bool found() const { return Found; }

  bool VisitCallExpr(CallExpr *CE) {
    if (Found) return false;
    if (!isAfter(CE->getBeginLoc())) return true;
    if (isBufferCopyCall(CE)) {
      for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
        const Expr *Arg = CE->getArg(i);
        const Expr *DataBase = nullptr;
        if (containsFieldAccess(Arg, "data_pointer", DataBase) &&
            sameExpr(DataBase, Base, Ctx)) {
          Found = true;
          return false;
        }
      }
    }
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (Found) return false;
    if (BO->getOpcode() != BO_Assign) return true;
    if (!isAfter(BO->getBeginLoc())) return true;
    const Expr *RHS = BO->getRHS();
    const Expr *DataBase = nullptr;
    if (containsFieldAccess(RHS, "data_pointer", DataBase) &&
        sameExpr(DataBase, Base, Ctx)) {
      Found = true;
      return false;
    }
    if (isWholeStructCopy(BO, Base, Ctx)) {
      Found = true;
      return false;
    }
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL check on data pointer",
                       "API Misuse")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD) return;
  const Stmt *Body = FD->getBody();
  if (!Body) return;

  ASTContext &Ctx = Mgr.getASTContext();

  GuardFinder GF(Ctx);
  GF.TraverseStmt(const_cast<Stmt*>(Body));

  if (GF.Guards.empty()) return;

  for (const auto &G : GF.Guards) {
    UseFinder UF(G.Base, G.Loc, Ctx);
    UF.TraverseStmt(const_cast<Stmt*>(Body));
    if (UF.found()) {
      PathDiagnosticLocation Loc(G.Loc, Mgr.getSourceManager());
      auto R = std::make_unique<BasicBugReport>(
          *BT, "Unchecked data pointer used without NULL check", Loc);
      BR.emitReport(std::move(R));
      break; // report one per function
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL check on data pointer before use",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "length_field": {"names": ["len"], "description": "field storing the length of a buffer"},
  "data_pointer": {"names": ["data"], "description": "pointer to the buffer data"},
  "buffer_copy": {"names": ["memcpy"], "description": "function that copies memory from a source to a destination"},
  "error_return": {"names": ["CURLE_BAD_FUNCTION_ARGUMENT", "CURLE_OUT_OF_MEMORY"], "description": "error code returned when validation fails"},
  "copy_flag": {"names": ["CURL_BLOB_COPY"], "description": "flag indicating that the buffer data should be copied"},
  "allocator": {"names": ["curlx_malloc"], "description": "memory allocation function"},
  "deallocator": {"names": ["curlx_safefree"], "description": "memory deallocation function"},
  "validation_guard": {"names": [], "description": "conditional check that validates input arguments; missing data pointer check is the bug"}
}
*/
