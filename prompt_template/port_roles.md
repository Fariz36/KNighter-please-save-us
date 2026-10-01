# Instruction

A Clang Static Analyzer checker was generated from a bug fix in **{{source_project}}**. It does not
hardcode that project's API: it asks about **roles** (for example "is this call an allocator?"), and
a roles file maps each role to the project's function or macro names.

Map every role to the names that play **the same role** in **{{target_project}}**, so that the checker
detects the same kind of bug there. Choose names **only** from the candidates listed for that role
(they were extracted from the target's headers). Use an empty list when the target has no
equivalent: a missing mapping only makes the checker silent, while a wrong one creates false alarms.
Include several names when the target has several equivalents (e.g. different allocator variants).

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
