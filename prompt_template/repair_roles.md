# Instruction

The following Clang Static Analyzer checker hardcodes project-specific identifiers in its logic,
so it cannot be reused on other projects. Rewrite it so that every listed identifier is referred to
through a role, following the rules in `Project Roles`. Keep the detection logic otherwise unchanged:
the checker must still report exactly the same bugs on this project. Every name you remove from the
logic must appear in the `KNIGHTER_ROLES` block, under a role with a project-independent description.

{{roles_guidance}}

# Hardcoded Identifiers

{{findings}}

# Checker

```cpp
{{checker_code}}
```

# Formatting

Return the complete fixed checker in a single ```cpp code block, including the `KNIGHTER_ROLES` block
at the end of the file.
