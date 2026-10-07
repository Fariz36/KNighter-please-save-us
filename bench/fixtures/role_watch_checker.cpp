#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "knighter/roles.h"

using namespace clang;
using namespace ento;

namespace {
class SAGenTestChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;
public:
  SAGenTestChecker() : BT(new BugType(this, "Watched call", "Test")) {}
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (!knighter::callIsRole(Call, "watched"))
      return;
    ExplodedNode *N = C.generateNonFatalErrorNode();
    if (!N)
      return;
    C.emitReport(std::make_unique<PathSensitiveBugReport>(*BT, "call to a watched function", N));
  }
};
} // namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>("custom.SAGenTestChecker", "roles E2E test", "");
}
extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;

/* KNIGHTER_ROLES
{"watched": {"names": ["memcpy"], "description": "function whose calls the test reports"}}
*/
