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

#include "clang/AST/Decl.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
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

// Whether the callee of `Call` plays `Role`.
inline bool callIsRole(const clang::ento::CallEvent &Call, llvm::StringRef Role) {
  if (const clang::IdentifierInfo *II = Call.getCalleeIdentifier())
    return isRole(Role, II->getName());
  return false;
}

// Whether the declaration (function, field, variable) plays `Role`.
inline bool declIsRole(const clang::NamedDecl *D, llvm::StringRef Role) {
  if (!D || !D->getIdentifier())
    return false;
  return isRole(Role, D->getName());
}

} // namespace knighter
