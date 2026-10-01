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
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

// Collect the set of "wide" VarDecls referenced anywhere inside a stmt subtree.
class WideRefCollector : public RecursiveASTVisitor<WideRefCollector> {
public:
  llvm::SmallPtrSetImpl<const VarDecl *> &WideVars;
  bool &SeenWideLiteral;

  WideRefCollector(llvm::SmallPtrSetImpl<const VarDecl *> &WV,
                   bool &SL)
      : WideVars(WV), SeenWideLiteral(SL) {}

  bool VisitDeclRefExpr(DeclRefExpr *DRE) {
    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!VD)
      return true;
    QualType QT = VD->getType();
    if (!QT.isNull() && QT->isIntegerType()) {
      unsigned W = QT->isSpecificBuiltinType(BuiltinType::LongLong) ||
                           QT->isSpecificBuiltinType(BuiltinType::ULongLong)
                       ? (QT->isSpecificBuiltinType(BuiltinType::ULongLong)
                              ? 64u
                              : 64u)
                       : 0u;
      const ASTContext &Ctx = VD->getASTContext();
      unsigned Bits = Ctx.getTypeSize(QT);
      if (Bits >= 64) {
        WideVars.insert(VD);
      }
      (void)W;
    }
    return true;
  }

  bool VisitIntegerLiteral(IntegerLiteral *IL) {
    const llvm::APInt &V = IL->getValue();
    if (V.getActiveBits() > 31) {
      SeenWideLiteral = true;
    }
    return true;
  }

  // Detect macros that expand to large literals which clang models as
  // CharacterLiteral or similar — handled by VisitIntegerLiteral above.
};

class IntCounterUseCollector
    : public RecursiveASTVisitor<IntCounterUseCollector> {
public:
  const llvm::SmallPtrSetImpl<const VarDecl *> &NarrowCounters;
  bool CounterUsed = false;

  // Also: whether any expression containing a counter also contains a wide var
  bool MixedWithWide = false;
  llvm::SmallPtrSetImpl<const VarDecl *> &WideVars;
  bool &SeenWideLiteral;

  IntCounterUseCollector(const llvm::SmallPtrSetImpl<const VarDecl *> &NC,
                         llvm::SmallPtrSetImpl<const VarDecl *> &WV,
                         bool &SL)
      : NarrowCounters(NC), WideVars(WV), SeenWideLiteral(SL) {}

  bool VisitDeclRefExpr(DeclRefExpr *DRE) {
    const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (VD && NarrowCounters.count(VD)) {
      CounterUsed = true;
    }
    return true;
  }
};

} // end anonymous namespace

namespace {

class SAGenTestChecker
    : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Integer Overflow in Loop Counter",
                       "Integer Overflow")) {}

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const;

private:
  bool isNarrowIntType(QualType QT) const {
    return QT->isSpecificBuiltinType(BuiltinType::Int);
  }

  bool isWideIntegerType(QualType QT, const ASTContext &Ctx) const {
    if (QT.isNull())
      return false;
    if (!QT->isIntegerType())
      return false;
    unsigned Bits = Ctx.getTypeSize(QT);
    return Bits >= 64;
  }

  bool stmtContainsWideValue(const Stmt *S,
                             llvm::SmallPtrSetImpl<const VarDecl *> &WideVars,
                             const ASTContext &Ctx) const;

  void reportBug(const VarDecl *NarrowCounter, BugReporter &BR,
                 const ASTContext &Ctx) const;
};

} // end anonymous namespace

// Walk an expression subtree and gather:
//  - wide variable decls referenced (type width >= 64)
//  - existence of a literal > INT_MAX
// Returns true if any wide value was found.
static bool scanForWideValues(const Stmt *S,
                              llvm::SmallPtrSetImpl<const VarDecl *> &WideVars,
                              bool &SeenWideLiteral,
                              const ASTContext &Ctx) {
  if (!S)
    return false;

  // Manual recursive scan (avoid needing a check-specific visitor class).
  SmallVector<const Stmt *, 32> Worklist;
  Worklist.push_back(S);

  while (!Worklist.empty()) {
    const Stmt *Cur = Worklist.pop_back_val();
    if (!Cur)
      continue;

    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Cur)) {
      const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
      if (VD && !VD->getType().isNull() && VD->getType()->isIntegerType()) {
        unsigned Bits = Ctx.getTypeSize(VD->getType());
        if (Bits >= 64)
          WideVars.insert(VD);
      }
    } else if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(Cur)) {
      const llvm::APInt &V = IL->getValue();
      // Treat any literal whose value can't fit in 32-bit signed as wide.
      if (V.getSignificantBits() > 32 ||
          V.getActiveBits() > 31 ||
          V.getSExtValue() > (int64_t)INT_MAX ||
          V.getSExtValue() < (int64_t)INT_MIN) {
        SeenWideLiteral = true;
      }
    }

    for (const Stmt *Child : Cur->children()) {
      Worklist.push_back(Child);
    }
  }
  return !WideVars.empty() || SeenWideLiteral;
}

// This is redundant with above but kept for structure clarity.
bool SAGenTestChecker::stmtContainsWideValue(
    const Stmt *S, llvm::SmallPtrSetImpl<const VarDecl *> &WideVars,
    const ASTContext &Ctx) const {
  bool SeenWideLiteral = false;
  return scanForWideValues(S, WideVars, SeenWideLiteral, Ctx);
}

void SAGenTestChecker::reportBug(const VarDecl *NarrowCounter,
                                 BugReporter &BR,
                                 const ASTContext &Ctx) const {
  if (!BT)
    return;

  PathDiagnosticLocation L =
      PathDiagnosticLocation::create(NarrowCounter, BR.getSourceManager());
  auto Report = std::make_unique<BasicBugReport>(
      *BT,
      "Loop counter of type 'int' may overflow; use i64 to match size "
      "variables.",
      L);
  Report->addRange(NarrowCounter->getSourceRange());
  BR.emitReport(std::move(Report));
}

void SAGenTestChecker::checkASTCodeBody(const Decl *D,
                                        AnalysisManager &Mgr,
                                        BugReporter &BR) const {
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(D);
  if (!FD || !FD->hasBody())
    return;

  ASTContext &Ctx = Mgr.getASTContext();
  const Stmt *Body = FD->getBody();
  if (!Body)
    return;

  // Find all ForStmt nodes in the body.
  SmallVector<const ForStmt *, 16> ForStmts;
  SmallVector<const Stmt *, 32> Worklist;
  Worklist.push_back(Body);
  while (!Worklist.empty()) {
    const Stmt *Cur = Worklist.pop_back_val();
    if (!Cur)
      continue;
    if (const ForStmt *FS = dyn_cast<ForStmt>(Cur))
      ForStmts.push_back(FS);
    for (const Stmt *Child : Cur->children())
      Worklist.push_back(Child);
  }

  for (const ForStmt *FS : ForStmts) {
    // 1. Collect narrow int counters declared in the Init part.
    llvm::SmallPtrSet<const VarDecl *, 4> NarrowCounters;
    const Stmt *Init = FS->getInit();
    if (Init) {
      if (const DeclStmt *DS = dyn_cast<DeclStmt>(Init)) {
        for (const Decl *Dcl : DS->decls()) {
          const VarDecl *VD = dyn_cast<VarDecl>(Dcl);
          if (VD && isNarrowIntType(VD->getType()))
            NarrowCounters.insert(VD);
        }
      }
    }
    if (NarrowCounters.empty())
      continue;

    // 2. Collect wide variables/literals used anywhere in the loop's
    //    condition, body, and inc.
    llvm::SmallPtrSet<const VarDecl *, 8> WideVars;
    bool SeenWideLiteral = false;
    scanForWideValues(FS->getCond(), WideVars, SeenWideLiteral, Ctx);
    scanForWideValues(FS->getBody(), WideVars, SeenWideLiteral, Ctx);
    scanForWideValues(FS->getInc(), WideVars, SeenWideLiteral, Ctx);

    if (WideVars.empty() && !SeenWideLiteral)
      continue;

    // 3. Find narrow counters used together with a wide value in the
    //    same expression. Walk the loop body looking for expressions
    //    that reference both a narrow counter and a wide value.
    bool FoundMix = false;

    // Walk all subexpressions of body/cond/inc.
    SmallVector<const Stmt *, 32> SubWorklist;
    if (FS->getCond())
      SubWorklist.push_back(FS->getCond());
    if (FS->getBody())
      SubWorklist.push_back(FS->getBody());
    if (FS->getInc())
      SubWorklist.push_back(FS->getInc());

    while (!SubWorklist.empty()) {
      const Stmt *Cur = SubWorklist.pop_back_val();
      if (!Cur)
        continue;

      // For each node, collect the set of declared refs (narrow counters)
      // and check whether wide values participate in the same node.
      llvm::SmallPtrSet<const VarDecl *, 4> CurCounters;
      llvm::SmallPtrSet<const VarDecl *, 8> CurWideVars;
      bool CurWideLit = false;

      SmallVector<const Stmt *, 16> InnerWorklist;
      InnerWorklist.push_back(Cur);
      while (!InnerWorklist.empty()) {
        const Stmt *Inner = InnerWorklist.pop_back_val();
        if (!Inner)
          continue;
        if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Inner)) {
          const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl());
          if (VD) {
            if (isNarrowIntType(VD->getType()) && NarrowCounters.count(VD))
              CurCounters.insert(VD);
            if (!VD->getType().isNull() && VD->getType()->isIntegerType()) {
              unsigned Bits = Ctx.getTypeSize(VD->getType());
              if (Bits >= 64)
                CurWideVars.insert(VD);
            }
          }
        } else if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(Inner)) {
          const llvm::APInt &V = IL->getValue();
          if (V.getSignificantBits() > 32 ||
              V.getActiveBits() > 31 ||
              V.getSExtValue() > (int64_t)INT_MAX) {
            CurWideLit = true;
          }
        }
        for (const Stmt *C : Inner->children())
          InnerWorklist.push_back(C);
      }

      if (!CurCounters.empty() &&
          (!CurWideVars.empty() || CurWideLit)) {
        FoundMix = true;
        break;
      }

      for (const Stmt *C : Cur->children())
        SubWorklist.push_back(C);
    }

    if (!FoundMix)
      continue;

    // 4. Report each narrow counter as the location.
    for (const VarDecl *NC : NarrowCounters) {
      reportBug(NC, BR, Ctx);
    }
  }
}

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects potential integer overflow in narrow `int` loop counters "
      "mixed with 64-bit size variables",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
