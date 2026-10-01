- **Null-pointer dereference feasibility** (if applicable):
  1. **Identify the pointer source** and the return convention of the producing function(s) in this path (e.g., returns **NULL** on failure, returns an error code and leaves an out-parameter unset, or is documented never-null).
  2. **Check real-world feasibility in this project**:
     - Enumerate concrete conditions under which the producer can return **NULL** here (e.g., allocation failure, malformed or hostile input, missing optional configuration or resource, an optional build feature being disabled, error paths in callers, API misuse by the library user).
     - Verify whether those conditions can occur given how the function is reached (public API entry points, callbacks, initialization order) and the project's own helpers and assertion macros.
  3. **Lifetime & concurrency**: consider teardown and cleanup paths, ownership/reference counting conventions, callbacks, and whether the pointer can become invalid/NULL across re-entrancy or concurrent use.
  4. If the producer is provably non-NULL in this context (by contract, preceding checks, or assertion macros that abort), classify as **false positive**.

