// KNighter project roles: project-specific API names live outside checker logic.
//
// A checker asks semantic questions ("is this call an allocator?") instead of
// comparing against a project's function names. The names come from a JSON
// file named by the KNIGHTER_ROLES environment variable:
//
//   {"allocator": ["malloc", "xmlMalloc"], "deallocator": ["free", "xmlFree"]}
//
// KNighter writes that file from the checker's `KNIGHTER_ROLES` comment block
// for the project the checker was generated from; porting a checker to
// another project only means supplying that project's roles file.
//
// Without a roles file every role query is false, so the checker stays inert
// instead of crashing.
#pragma once

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdlib>
#include <string>
#include <vector>

namespace knighter {

using RoleMap = llvm::StringMap<std::vector<std::string>>;

inline RoleMap loadRoles() {
  RoleMap Roles;
  const char *Path = std::getenv("KNIGHTER_ROLES");
  if (!Path || !*Path)
    return Roles;
  auto Buffer = llvm::MemoryBuffer::getFile(Path);
  if (!Buffer) {
    llvm::errs() << "knighter: cannot read KNIGHTER_ROLES file " << Path << "\n";
    return Roles;
  }
  llvm::Expected<llvm::json::Value> Parsed =
      llvm::json::parse((*Buffer)->getBuffer());
  if (!Parsed) {
    llvm::errs() << "knighter: invalid roles JSON in " << Path << ": "
                 << llvm::toString(Parsed.takeError()) << "\n";
    return Roles;
  }
  const llvm::json::Object *Obj = Parsed->getAsObject();
  if (!Obj)
    return Roles;
  for (const auto &Entry : *Obj) {
    std::vector<std::string> Names;
    if (const llvm::json::Array *Arr = Entry.second.getAsArray())
      for (const llvm::json::Value &V : *Arr)
        if (auto S = V.getAsString())
          Names.push_back(S->str());
    Roles[Entry.first.str()] = std::move(Names);
  }
  return Roles;
}

// Loaded once per process (the analyzer is single-threaded per TU).
inline const RoleMap &roles() {
  static const RoleMap Roles = loadRoles();
  return Roles;
}

// Names bound to a role (empty if the role is unknown).
inline llvm::ArrayRef<std::string> roleNames(llvm::StringRef Role) {
  static const std::vector<std::string> Empty;
  auto It = roles().find(Role);
  return It == roles().end() ? llvm::ArrayRef<std::string>(Empty)
                             : llvm::ArrayRef<std::string>(It->second);
}

// Whether `Name` (a function, macro or field name) plays `Role` in this project.
inline bool isRole(llvm::StringRef Role, llvm::StringRef Name) {
  if (Name.empty())
    return false;
  for (const std::string &Candidate : roleNames(Role))
    if (Name == Candidate)
      return true;
  return false;
}

// Whether the declaration (function, field, variable) plays `Role`.
inline bool declIsRole(const clang::NamedDecl *D, llvm::StringRef Role) {
  if (!D || !D->getIdentifier())
    return false;
  return isRole(Role, D->getName());
}

// Whether a macro the code at `Loc` was written through plays `Role`.
// The analyzer sees preprocessed code, so a call written as `curlx_free(p)`
// reaches the checker as `free(p)`; the macro name survives only in the
// source location's expansion chain. Macro arguments are skipped: in
// `CHECK(foo(x))` the call `foo(x)` was written by the user, not by CHECK.
inline bool macroIsRole(clang::SourceLocation Loc, const clang::ASTContext &Ctx,
                        llvm::StringRef Role) {
  const clang::SourceManager &SM = Ctx.getSourceManager();
  for (unsigned Depth = 0; Loc.isMacroID() && Depth < 16; ++Depth) {
    if (SM.isMacroArgExpansion(Loc)) {
      Loc = SM.getImmediateSpellingLoc(Loc);
      continue;
    }
    if (isRole(Role, clang::Lexer::getImmediateMacroName(Loc, SM, Ctx.getLangOpts())))
      return true;
    Loc = SM.getImmediateMacroCallerLoc(Loc);
  }
  return false;
}

// Whether the call plays `Role`: its callee function, the variable or field
// holding the function pointer it calls through (libxml2's `xmlFree` is a
// global function pointer), or a macro it was written through.
inline bool callExprIsRole(const clang::CallExpr *CE, llvm::StringRef Role,
                           const clang::ASTContext &Ctx) {
  if (!CE)
    return false;
  if (declIsRole(CE->getDirectCallee(), Role))
    return true;
  if (const clang::Expr *Callee = CE->getCallee()) {
    Callee = Callee->IgnoreParenImpCasts();
    if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(Callee))
      if (UO->getOpcode() == clang::UO_Deref)
        Callee = UO->getSubExpr()->IgnoreParenImpCasts();
    if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(Callee))
      if (declIsRole(DRE->getDecl(), Role))
        return true;
    if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(Callee))
      if (declIsRole(ME->getMemberDecl(), Role))
        return true;
  }
  return macroIsRole(CE->getBeginLoc(), Ctx, Role);
}

// Whether the callee of `Call` plays `Role` (same matching as callExprIsRole).
inline bool callIsRole(const clang::ento::CallEvent &Call, llvm::StringRef Role) {
  if (const clang::IdentifierInfo *II = Call.getCalleeIdentifier())
    if (isRole(Role, II->getName()))
      return true;
  if (const auto *CE = llvm::dyn_cast_or_null<clang::CallExpr>(Call.getOriginExpr()))
    return callExprIsRole(CE, Role, Call.getState()->getStateManager().getContext());
  return false;
}

} // namespace knighter
