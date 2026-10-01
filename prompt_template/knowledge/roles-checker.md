# Project Roles (mandatory)

The checker must not hardcode project-specific identifiers. Project functions, macros, types and
fields are referred to only through **roles**, so the same checker can run on another project with a
different roles file. Standard C/C++ library names (malloc, free, memcpy, strlen, std::vector, ...)
may still be used directly.

Use roles from this standard vocabulary whenever one fits (they map well to other projects):
`allocator`, `deallocator`, `reallocator`, `duplicator` (returns a new copy, e.g. strdup-like),
`null_on_failure` (may return NULL), `error_setter` (records/reports an error, printf-like),
`aborting_assert` (stops execution when its condition is false), `length_of`, `buffer_copy`,
`bounded_copy`, `lock`, `unlock`, `ref_get`, `ref_put`, `init`, `cleanup`, `container_insert`,
`container_remove`, `parser_input`, `untrusted_size`.
A role is an **API category that most C/C++ projects have**, not a description of this patch: name and
describe what *any* function in that category does (e.g. "frees memory or an object; the pointer must
not be used afterwards"), never which object, struct or call site it is in this project. Use at most 6
roles. Only invent a new role when no category fits, and then keep it equally generic.

Rules:
1. `#include "knighter/roles.h"` and query roles with:
   - `knighter::callIsRole(Call, "allocator")`: is the callee of `Call` an allocator?
   - `knighter::isRole("error_setter", Name)`: does this function/macro/field name play the role?
   - `knighter::declIsRole(D, "lock_field")`: does this `NamedDecl` play the role?
   - `knighter::roleNames("allocator")`: all names bound to the role (`ArrayRef<std::string>`).
2. Never write a project-specific name in a string literal or comparison in the checker logic
   (no `"git_error_set"`, no `getName() == "short_oid"`, no `startswith("Curl_")`).
3. Put the names this project uses into a `KNIGHTER_ROLES` comment block at the **end of the file**:
   a JSON object mapping each role to `{"names": [...], "description": "..."}`. The description must
   say what the role means independent of this project, so the role can be mapped to another project:

```cpp
/* KNIGHTER_ROLES
{
  "error_setter": {"names": ["git_error_set"], "description": "printf-style function that records an error message; its format arguments must be valid C strings"},
  "aborting_assert": {"names": ["GIT_ASSERT_ARG"], "description": "macro that returns/aborts when its argument is false, so the argument is non-null afterwards"}
}
*/
```

The KNighter build turns this block into the roles file the checker reads at analysis time.
