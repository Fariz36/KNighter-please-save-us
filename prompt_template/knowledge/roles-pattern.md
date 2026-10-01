# Project Roles (mandatory)

The checker will be reused on other C/C++ projects, so describe the bug pattern in terms of the
**roles** that project-specific functions, macros, types or fields play, not their names. 

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

In your answer, first state the pattern with roles (e.g. "the result of an `allocator` call is
dereferenced before a NULL check"), then list each role with the concrete names it has in this patch,
e.g. `allocator: xmlMalloc, xmlRealloc`. Standard C/C++ library functions (malloc, free, memcpy,
strlen, ...) may be named directly.
