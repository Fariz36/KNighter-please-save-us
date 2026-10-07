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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

static bool findFixedSlack(const Expr *E, int64_t &Slack) {
  if (!E)
    return false;
  E = E->IgnoreParenImpCasts();
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_Add) {
      const Expr *L = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *R = BO->getRHS()->IgnoreParenImpCasts();
      if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(L)) {
        Slack = IL->getValue().getSExtValue();
        return true;
      }
      if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(R)) {
        Slack = IL->getValue().getSExtValue();
        return true;
      }
    }
    if (findFixedSlack(BO->getLHS(), Slack))
      return true;
    if (findFixedSlack(BO->getRHS(), Slack))
      return true;
  }
  return false;
}

class BufferCapacityVisitor : public RecursiveASTVisitor<BufferCapacityVisitor> {
public:
  const VarDecl *CapacityVar = nullptr;
  const CallExpr *BufferGrowCall = nullptr;
  const BinaryOperator *CapacityAssign = nullptr;
  bool HasExponent = false;

  bool VisitCallExpr(CallExpr *CE) {
    if (!CE)
      return true;

    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD || !knighter::isRole("buffer_grow", FD->getName()))
      return true;

    for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
      const Expr *Arg = CE->getArg(i)->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Arg)) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          if (knighter::declIsRole(VD, "required_capacity")) {
            if (!CapacityVar)
              CapacityVar = VD;
            if (CapacityVar == VD)
              BufferGrowCall = CE;
            break;
          }
        }
      }
    }
    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (!BO)
      return true;

    if (BO->getOpcode() == BO_Assign) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          if (knighter::declIsRole(VD, "required_capacity")) {
            if (!CapacityVar || CapacityVar == VD) {
              CapacityVar = VD;
              if (!CapacityAssign)
                CapacityAssign = BO;
            }
          }
        }
      }
    }

    if (BO->getOpcode() == BO_Assign && !HasExponent) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();

      if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(LHS)) {
        if (UO->getOpcode() == UO_Deref) {
          const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
          if (const UnaryOperator *Inc = dyn_cast<UnaryOperator>(Sub)) {
            if (Inc->getOpcode() == UO_PostInc ||
                Inc->getOpcode() == UO_PreInc) {
              const Expr *Ptr = Inc->getSubExpr()->IgnoreParenImpCasts();
              if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Ptr)) {
                if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
                  if (knighter::declIsRole(VD, "write_pointer") &&
                      containsDigitSet(RHS)) {
                    HasExponent = true;
                  }
                }
              }
            }
          }
        }
      }
    }

    return true;
  }

private:
  bool containsDigitSet(const Expr *E) const {
    if (!E)
      return false;
    E = E->IgnoreParenImpCasts();

    if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
      const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base)) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          if (knighter::declIsRole(VD, "digit_set"))
            return true;
        }
      }
    }

    for (const Stmt *Child : E->children()) {
      if (const Expr *CE = dyn_cast<Expr>(Child)) {
        if (containsDigitSet(CE))
          return true;
      }
    }
    return false;
  }
};

class SAGenTestChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Buffer capacity underestimation",
                       "Buffer Overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD)
    return;

  Stmt *Body = FD->getBody();
  if (!Body)
    return;

  BufferCapacityVisitor V;
  V.TraverseStmt(Body);

  if (!V.HasExponent || !V.BufferGrowCall || !V.CapacityAssign)
    return;

  int64_t Slack = 0;
  if (!findFixedSlack(V.CapacityAssign->getRHS(), Slack))
    return;

  if (Slack < 9) {
    PathDiagnosticLocation Loc(V.CapacityAssign->getBeginLoc(),
                               BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT,
        "Buffer capacity calculation underestimates optional formatting bytes; "
        "possible buffer overflow.",
        Loc);
    Report->addRange(V.CapacityAssign->getSourceRange());
    BR.emitReport(std::move(Report));
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects buffer capacity underestimation leading to possible overflow",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "buffer_grow": {
    "names": ["sqlite3StrAccumEnlargeIfNeeded"],
    "description": "Function that ensures the output buffer has at least the requested capacity."
  },
  "required_capacity": {
    "names": ["szBufNeeded"],
    "description": "Variable holding the computed required capacity for an output buffer, passed to a buffer grow function."
  },
  "write_pointer": {
    "names": ["bufpt"],
    "description": "Pointer used to write characters into the output buffer."
  },
  "digit_set": {
    "names": ["aDigits"],
    "description": "Array of digit characters used by the formatter."
  },
  "output_buffer": {
    "names": ["zOut"],
    "description": "Pointer to the output buffer being written to."
  }
}
*/
