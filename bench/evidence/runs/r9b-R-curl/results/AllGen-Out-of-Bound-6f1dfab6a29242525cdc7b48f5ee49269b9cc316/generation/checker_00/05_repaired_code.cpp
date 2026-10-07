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
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Helper: ignore parentheses and implicit casts
static const Expr *ignoreParenImpCasts(const Expr *E) {
  if (!E) return nullptr;
  return E->IgnoreParenImpCasts();
}

// Flatten && operands in evaluation order
static void collectAndOperands(const Expr *E,
                               llvm::SmallVectorImpl<const Expr *> &Ops) {
  if (!E) return;
  E = E->IgnoreParenImpCasts();
  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_LAnd) {
      collectAndOperands(BO->getLHS(), Ops);
      collectAndOperands(BO->getRHS(), Ops);
      return;
    }
  }
  Ops.push_back(E);
}

// Find a positive constant-index ArraySubscriptExpr on a pointer variable
static bool findPositiveSubscript(const Expr *E, CheckerContext &C,
                                  const ArraySubscriptExpr *&OutASE,
                                  const VarDecl *&OutPtr) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E)) {
    llvm::APSInt Idx;
    if (EvaluateExprToInt(Idx, ASE->getIdx(), C) && Idx.isStrictlyPositive()) {
      const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
      if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base)) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          OutASE = ASE;
          OutPtr = VD;
          return true;
        }
      }
    }
  }
  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildExpr = dyn_cast<Expr>(Child)) {
      if (findPositiveSubscript(ChildExpr, C, OutASE, OutPtr))
        return true;
    }
  }
  return false;
}

// Find a call to a string_search role function
static const CallExpr *findStringSearchCall(const Expr *E, CheckerContext &C) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
  if (const CallExpr *CE = dyn_cast<CallExpr>(E)) {
    if (knighter::callExprIsRole(CE, "string_search", C.getASTContext()))
      return CE;
  }
  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildExpr = dyn_cast<Expr>(Child)) {
      if (const CallExpr *CE = findStringSearchCall(ChildExpr, C))
        return CE;
    }
  }
  return nullptr;
}

// Check recursively whether an expression is derived from a parser_input call
static bool containsParserInputCall(const Expr *E, CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  if (const CallExpr *CE = dyn_cast<CallExpr>(E)) {
    if (knighter::callExprIsRole(CE, "parser_input", C.getASTContext()))
      return true;
  }
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (const Expr *Init = VD->getInit()) {
        if (containsParserInputCall(Init, C))
          return true;
      }
    }
  }
  for (const Stmt *Child : E->children()) {
    if (const Expr *ChildExpr = dyn_cast<Expr>(Child)) {
      if (containsParserInputCall(ChildExpr, C))
        return true;
    }
  }
  return false;
}

// Check whether an expression is P[0] and extract P
static bool isZeroSubscriptOf(const Expr *E, const VarDecl *&OutPtr,
                              CheckerContext &C) {
  if (!E) return false;
  E = E->IgnoreParenImpCasts();
  const ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(E);
  if (!ASE) return false;
  llvm::APSInt Idx;
  if (!EvaluateExprToInt(Idx, ASE->getIdx(), C)) return false;
  if (!Idx.isZero()) return false;
  const Expr *Base = ASE->getBase()->IgnoreParenImpCasts();
  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base);
  if (!DRE) return false;
  const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
  if (!VD) return false;
  OutPtr = VD;
  return true;
}

// Build a map from pointer variable P to guard variable G where G = P[0]
static void buildGuardMap(const CompoundStmt *CS, const IfStmt *IS,
                          llvm::DenseMap<const VarDecl *, const VarDecl *> &GuardMap,
                          CheckerContext &C) {
  for (const Stmt *S : CS->body()) {
    if (S == IS) break;
    if (const DeclStmt *DS = dyn_cast<DeclStmt>(S)) {
      for (const Decl *D : DS->decls()) {
        if (const VarDecl *VD = dyn_cast<VarDecl>(D)) {
          if (const Expr *Init = VD->getInit()) {
            const VarDecl *Ptr = nullptr;
            if (isZeroSubscriptOf(Init, Ptr, C)) {
              GuardMap[Ptr] = VD;
            }
          }
        }
      }
    }
    if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->getOpcode() == BO_Assign) {
        const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
        if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
          if (const VarDecl *G = dyn_cast<VarDecl>(DRE->getDecl())) {
            const VarDecl *Ptr = nullptr;
            if (isZeroSubscriptOf(BO->getRHS(), Ptr, C)) {
              GuardMap[Ptr] = G;
            }
          }
        }
      }
    }
  }
}

// Check whether the pointer P is incremented before the IfStmt
static bool hasIncrementBefore(const VarDecl *P, const IfStmt *IS,
                               const CompoundStmt *CS, CheckerContext &C) {
  for (const Stmt *S : CS->body()) {
    if (S == IS) break;
    if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(S)) {
      if (UO->getOpcode() == UO_PostInc || UO->getOpcode() == UO_PreInc) {
        const Expr *Sub = UO->getSubExpr()->IgnoreParenImpCasts();
        if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Sub)) {
          if (DRE->getDecl() == P) return true;
        }
      }
    }
    if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
      if (BO->getOpcode() == BO_AddAssign) {
        const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
        if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
          if (DRE->getDecl() == P) {
            llvm::APSInt Val;
            if (EvaluateExprToInt(Val, BO->getRHS(), C) && Val == 1)
              return true;
          }
        }
      }
    }
  }
  return false;
}

// Check if P is initialized/assigned from a string_search whose first argument
// derives from parser_input, and P is incremented before the branch.
static bool isAdvancedSearchPtr(const VarDecl *P, const IfStmt *IS,
                                CheckerContext &C) {
  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
  if (!CS) return false;

  const CallExpr *SearchCall = nullptr;

  if (const Expr *Init = P->getInit()) {
    SearchCall = findStringSearchCall(Init, C);
  }

  if (!SearchCall) {
    for (const Stmt *S : CS->body()) {
      if (S == IS) break;
      if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
        if (BO->getOpcode() == BO_Assign) {
          const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
          if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
            if (DRE->getDecl() == P) {
              SearchCall = findStringSearchCall(BO->getRHS(), C);
              if (SearchCall) break;
            }
          }
        }
      }
    }
  }

  if (!SearchCall) return false;
  if (SearchCall->getNumArgs() < 1) return false;
  if (!containsParserInputCall(SearchCall->getArg(0), C)) return false;
  if (!hasIncrementBefore(P, IS, CS, C)) return false;

  return true;
}

// Direct non-NUL guard: P[0] used as a boolean, or P[0] != 0
static bool isDirectNonNullGuard(const Expr *E, const VarDecl *P,
                                 CheckerContext &C) {
  E = E->IgnoreParenImpCasts();
  const VarDecl *Ptr = nullptr;
  if (isZeroSubscriptOf(E, Ptr, C) && Ptr == P)
    return true;

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    if (BO->getOpcode() == BO_NE) {
      const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
      const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
      Ptr = nullptr;
      if (isZeroSubscriptOf(LHS, Ptr, C) && Ptr == P) {
        if (RHS->isNullPointerConstant(C.getASTContext(),
                                       Expr::NPC_ValueDependentIsNull))
          return true;
      }
      Ptr = nullptr;
      if (isZeroSubscriptOf(RHS, Ptr, C) && Ptr == P) {
        if (LHS->isNullPointerConstant(C.getASTContext(),
                                       Expr::NPC_ValueDependentIsNull))
          return true;
      }
    }
  }
  return false;
}

// Check if an operand guards a subsequent access to P
static bool isGuarded(const Expr *Op, const VarDecl *P,
                      const llvm::DenseMap<const VarDecl *, const VarDecl *> &GuardMap,
                      CheckerContext &C) {
  if (isDirectNonNullGuard(Op, P, C))
    return true;

  const Expr *E = Op->IgnoreParenImpCasts();
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *G = dyn_cast<VarDecl>(DRE->getDecl())) {
      auto It = GuardMap.find(P);
      if (It != GuardMap.end() && It->second == G)
        return true;
    }
  }
  return false;
}

class SAGenTestChecker : public Checker<check::BranchCondition> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Out-of-bounds read after string_search delimiter",
                       "Memory safety")) {}

  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

} // end anonymous namespace

void SAGenTestChecker::checkBranchCondition(const Stmt *Condition,
                                            CheckerContext &C) const {
  const Expr *CondE = dyn_cast<Expr>(Condition);
  if (!CondE) return;

  const IfStmt *IS = findSpecificTypeInParents<IfStmt>(Condition, C);
  if (!IS) return;

  const CompoundStmt *CS = findSpecificTypeInParents<CompoundStmt>(IS, C);
  if (!CS) return;

  llvm::DenseMap<const VarDecl *, const VarDecl *> GuardMap;
  buildGuardMap(CS, IS, GuardMap, C);

  llvm::SmallVector<const Expr *, 8> Operands;
  collectAndOperands(CondE, Operands);

  for (unsigned i = 0; i < Operands.size(); ++i) {
    const Expr *Op = Operands[i];
    const ArraySubscriptExpr *ASE = nullptr;
    const VarDecl *Ptr = nullptr;
    if (!findPositiveSubscript(Op, C, ASE, Ptr))
      continue;

    if (!isAdvancedSearchPtr(Ptr, IS, C))
      continue;

    bool Guarded = false;
    for (unsigned j = 0; j < i; ++j) {
      if (isGuarded(Operands[j], Ptr, GuardMap, C)) {
        Guarded = true;
        break;
      }
    }
    if (Guarded)
      continue;

    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;

    auto report = std::make_unique<PathSensitiveBugReport>(
        *BT, "Potential out-of-bounds read after string_search delimiter", N);
    report->addRange(ASE->getSourceRange());
    C.emitReport(std::move(report));
    return;
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects out-of-bounds reads after searching for a delimiter in untrusted input",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "string_search": {"names": ["strchr"], "description": "searches for the first occurrence of a character in a NUL-terminated string and returns a pointer to it, or NULL if not found"},
  "parser_input": {"names": ["curlx_dyn_ptr"], "description": "returns a pointer to the start of an untrusted NUL-terminated input buffer"},
  "error_setter": {"names": ["failf"], "description": "reports an error message with printf-style formatting"},
  "predicate": {"names": ["ISDIGIT"], "description": "character classification macro that tests whether a character is a decimal digit"}
}
*/
