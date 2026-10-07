# Instruction

A Clang Static Analyzer checker was generated from a bug fix in **{{source_project}}**. It does not
hardcode that project's API: it asks about **roles** (for example "is this call an allocator?"), and
a roles file maps each role to the project's function or macro names.

Map every role to the names that play **the same role** in **{{target_project}}**, so that the checker
detects the same kind of bug there. Prefer the candidates listed for that role (extracted from the target's
headers). You may also give another identifier of the target (e.g. a static function or a macro
the header scan missed) when you are sure it exists: every name is checked against the target's
source code and names that do not exist there are discarded. Use an empty list when the target has no
equivalent: a missing mapping only makes the checker silent, while a wrong one creates false alarms.
Include several names when the target has several equivalents (e.g. different allocator variants).

The ported checker scans the **whole** target project for new instances of the bug, so map each role to
its **category across the project**, not to the functions involved in one particular place where you
think the bug could occur. For a `deallocator`, list the project's general-purpose free functions and
wrappers (and the object-specific `*_free`/`*_destroy` functions that matter), not only the free
function of one object type. Macro wrappers and function-pointer variables (e.g. a `free` hook) are
valid names: the checker matches calls through them.

# Bug pattern the checker detects

{{pattern}}

# Roles

{{roles}}

# Formatting

Answer with a single ```json code block:

```json
{
  "<role>": {"names": ["<target name>", ...], "rationale": "<one sentence>"},
  ...
}
```
