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
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "knighter/roles.h"

#include <memory>

using namespace clang;
using namespace ento;
using namespace taint;

REGISTER_SET_WITH_PROGRAMSTATE(ContentConsumed, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(Unlinked, const MemRegion *)

namespace {

class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker()
      : BT(new BugType(this, "Missing detach-before-destroy",
                       "Memory Management")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportMissingDetach(const CallEvent &Call, CheckerContext &C) const;
};

static bool isLinkedNodeType(QualType QT) {
  QT = QT.getCanonicalType();
  if (const PointerType *PT = QT->getAs<PointerType>())
    QT = PT->getPointeeType();
  QT = QT.getUnqualifiedType();
  const RecordType *RT = QT->getAs<RecordType>();
  if (!RT)
    return false;
  const RecordDecl *RD = RT->getDecl();
  return RD && knighter::declIsRole(RD, "linked_node");
}

static const MemRegion *getBaseRegionFromExpr(const Expr *E, CheckerContext &C) {
  if (!E)
    return nullptr;
  const MemRegion *MR = getMemRegionFromExpr(E, C);
  if (!MR)
    return nullptr;
  return MR->getBaseRegion();
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call,
                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  if (knighter::callIsRole(Call, "content_consumer")) {
    bool Changed = false;
    for (unsigned I = 0, N = Call.getNumArgs(); I < N; ++I) {
      const Expr *Arg = Call.getArgExpr(I);
      if (!Arg)
        continue;

      // Direct linked-node argument.
      if (isLinkedNodeType(Arg->getType())) {
        const MemRegion *MR = getBaseRegionFromExpr(Arg, C);
        if (MR && !State->contains<ContentConsumed>(MR)) {
          State = State->add<ContentConsumed>(MR);
          Changed = true;
        }
      }

      // Argument like node->content: track the base node.
      const Expr *E = Arg->IgnoreParenImpCasts();
      if (const auto *ME = llvm::dyn_cast<MemberExpr>(E)) {
        const ValueDecl *MD = ME->getMemberDecl();
        if (MD && knighter::declIsRole(MD, "content_field")) {
          const Expr *Base = ME->getBase();
          if (Base && isLinkedNodeType(Base->getType())) {
            const MemRegion *MR = getBaseRegionFromExpr(Base, C);
            if (MR && !State->contains<ContentConsumed>(MR)) {
              State = State->add<ContentConsumed>(MR);
              Changed = true;
            }
          }
        }
      }
    }
    if (Changed)
      C.addTransition(State);
    return;
  }

  if (knighter::callIsRole(Call, "unlinker")) {
    if (Call.getNumArgs() > 0) {
      const Expr *Arg0 = Call.getArgExpr(0);
      const MemRegion *MR = getBaseRegionFromExpr(Arg0, C);
      if (MR && !State->contains<Unlinked>(MR)) {
        State = State->add<Unlinked>(MR);
        C.addTransition(State);
      }
    }
    return;
  }

  if (knighter::callIsRole(Call, "deallocator")) {
    const FunctionDecl *FD =
        llvm::dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!FD || !knighter::declIsRole(FD, "adder"))
      return;

    if (Call.getNumArgs() == 0)
      return;

    const Expr *Arg0 = Call.getArgExpr(0);
    const MemRegion *MR = getBaseRegionFromExpr(Arg0, C);
    if (!MR)
      return;

    if (State->contains<ContentConsumed>(MR) &&
        !State->contains<Unlinked>(MR)) {
      reportMissingDetach(Call, C);
    }
    return;
  }
}

void SAGenTestChecker::reportMissingDetach(const CallEvent &Call,
                                           CheckerContext &C) const {
  ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  auto Report = std::make_unique<PathSensitiveBugReport>(
      *BT, "Missing detach-before-destroy: node freed without unlinking first.",
      N);
  Report->addRange(Call.getSourceRange());
  C.emitReport(std::move(Report));
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects missing detach-before-destroy of linked nodes",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{
  "deallocator": {"names": ["xmlFreeNode"], "description": "function that frees a linked node object"},
  "unlinker": {"names": ["xmlUnlinkNodeInternal"], "description": "function that detaches a linked node from its container/tree by updating parent/prev/next links"},
  "linked_node": {"names": ["xmlNode"], "description": "struct type representing a node in a linked tree or container"},
  "content_consumer": {"names": ["xmlTextAddContent"], "description": "function that consumes or copies content from a linked node"},
  "adder": {"names": ["xmlAddChild"], "description": "function that adds a node to a container/tree, possibly freeing the node after consuming its content"},
  "content_field": {"names": ["content"], "description": "field of a linked node whose content is consumed"}
}
*/
