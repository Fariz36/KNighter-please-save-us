# Project Roles (mandatory)

The checker will be reused on other C/C++ projects, so describe the bug pattern in terms of the
**roles** that project-specific functions, macros, types or fields play, not their names. Examples of
roles: `allocator`, `deallocator`, `reallocator`, `error_setter` (records/reports an error),
`aborting_assert` (guard that stops execution), `null_on_failure` (returns NULL on failure),
`length_of`, `buffer_copy`, `lock` / `unlock`, `ref_get` / `ref_put`, `init` / `cleanup`. Invent a
precise snake_case role name when none fits.

In your answer, first state the pattern with roles (e.g. "the result of an `allocator` call is
dereferenced before a NULL check"), then list each role with the concrete names it has in this patch,
e.g. `allocator: xmlMalloc, xmlRealloc`. Standard C/C++ library functions (malloc, free, memcpy,
strlen, ...) may be named directly.
