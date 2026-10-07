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
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "knighter/roles.h"

#include <memory>
#include <vector>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool isInputStructType(QualType QT) {
  if (!QT->isPointerType())
    return false;

  QualType Pointee = QT->getPointeeType().getUnqualifiedType();
  const RecordType *RT = Pointee->getAs<RecordType>();
  if (!RT)
    return false;

  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return false;

  return knighter::declIsRole(RD, "input_struct");
}

static bool isFieldAccess(const Expr *E, const ParmVarDecl *Param,
                          StringRef Role) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  const MemberExpr *ME = dyn_cast<MemberExpr>(E);
  if (!ME)
    return false;

  const FieldDecl *FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
  if (!FD)
    return false;

  if (!knighter::declIsRole(FD, Role))
    return false;

  const Expr *Base = ME->getBase()->IgnoreParenImpCasts();
  if (ME->isArrow()) {
    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base);
    return DRE && DRE->getDecl() == Param;
  }

  const UnaryOperator *UO = dyn_cast<UnaryOperator>(Base);
  if (!UO || UO->getOpcode() != UO_Deref)
    return false;

  const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub);
  return DRE && DRE->getDecl() == Param;
}

static bool containsFieldAccess(const Expr *E, const ParmVarDecl *Param,
                                StringRef Role) {
  if (!E)
    return false;

  if (isFieldAccess(E, Param, Role))
    return true;

  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildE = dyn_cast<Expr>(Child)) {
      if (containsFieldAccess(ChildE, Param, Role))
        return true;
    }
  }
  return false;
}

static bool isDerefOfParam(const Expr *E, const ParmVarDecl *Param) {
  if (!E)
    return false;

  E = E->IgnoreParenImpCasts();
  const UnaryOperator *UO = dyn_cast<UnaryOperator>(E);
  if (!UO || UO->getOpcode() != UO_Deref)
    return false;

  const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub);
  return DRE && DRE->getDecl() == Param;
}

class MissingBufferSourceNullCheckVisitor
    : public RecursiveASTVisitor<MissingBufferSourceNullCheckVisitor> {
public:
  const ParmVarDecl *InputParam;
  bool hasLengthCheck = false;
  bool hasBufferSourceCheck = false;
  std::vector<const Stmt *> bufferSourceUses;

  explicit MissingBufferSourceNullCheckVisitor(const ParmVarDecl *P)
      : InputParam(P) {}

  bool VisitIfStmt(IfStmt *S) {
    const Expr *Cond = S->getCond();
    if (containsFieldAccess(Cond, InputParam, "length_of"))
      hasLengthCheck = true;
    if (containsFieldAccess(Cond, InputParam, "buffer_source"))
      hasBufferSourceCheck = true;
    return true;
  }

  bool VisitCallExpr(CallExpr *CE) {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD)
      return true;

    if (!knighter::declIsRole(FD, "copy_operation"))
      return true;

    for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
      const Expr *Arg = CE->getArg(i);
      if (containsFieldAccess(Arg, InputParam, "buffer_source")) {
        bufferSourceUses.push_back(CE);
        break;
      }
    }
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_Assign) {
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      if (isDerefOfParam(RHS, InputParam))
        bufferSourceUses.push_back(BO);
    }
    return true;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing NULL check on buffer source",
                       "Null Pointer")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  const ParmVarDecl *InputParam = nullptr;
  for (const ParmVarDecl *P : FD->parameters()) {
    if (isInputStructType(P->getType())) {
      InputParam = P;
      break;
    }
  }
  if (!InputParam)
    return;

  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  MissingBufferSourceNullCheckVisitor Visitor(InputParam);
  Visitor.TraverseStmt(Body);

  if (Visitor.hasLengthCheck && !Visitor.hasBufferSourceCheck &&
      !Visitor.bufferSourceUses.empty()) {
    const Stmt *Use = Visitor.bufferSourceUses.front();
    if (!Use)
      return;

    PathDiagnosticLocation Loc =
        PathDiagnosticLocation::createBegin(Use, BR.getSourceManager(),
                                            nullptr);
    auto Report = std::make_unique<BasicBugReport>(
        *BT, "Missing NULL check on buffer_source before use", Loc);
    Report->addRange(Use->getSourceRange());
    BR.emitReport(std::move(Report));
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing NULL check on buffer_source before use",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "input_struct": {"names": ["struct curl_blob"], "description": "caller-supplied struct containing a buffer source and length"},
  "buffer_source": {"names": ["data"], "description": "pointer field in the input struct that is used as a copy source or retained"},
  "length_of": {"names": ["len"], "description": "length field companion to buffer_source"},
  "length_limit": {"names": ["CURL_MAX_INPUT_LENGTH"], "description": "maximum allowed value for length_of"},
  "copy_flag": {"names": ["CURL_BLOB_COPY"], "description": "flag indicating whether buffer_source should be copied"},
  "copy_operation": {"names": ["memcpy"], "description": "function that copies from buffer_source"},
  "allocator": {"names": ["curlx_malloc"], "description": "memory allocation function"},
  "deallocator": {"names": ["curlx_safefree"], "description": "memory deallocation function"},
  "error_setter": {"names": ["CURLE_BAD_FUNCTION_ARGUMENT", "CURLE_OUT_OF_MEMORY"], "description": "error return codes for invalid arguments or allocation failure"}
}
*/
