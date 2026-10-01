# Instruction

Determine whether the static analyzer report is a real bug in {{project_description}} and matches the target bug pattern

Your analysis should:
- **Compare the report against the provided target bug pattern specification,** using the **buggy function (pre-patch)** and the **fix patch** as the reference.
- Explain your reasoning for classifying this as either:
  - **A true positive** (matches the target bug pattern **and** is a real bug), or
  - **A false positive** (does **not** match the target bug pattern **or** is **not** a real bug).

Please evaluate thoroughly using the following process:

- **First, understand** the reported code pattern and its control/data flow.
- **Then, compare** it against the target bug pattern characteristics.
- **Finally, validate** against the **pre-/post-patch** behavior:
  - The reported case demonstrates the same root cause pattern as the target bug pattern/function and would be addressed by a similar fix.

- **Numeric / bounds feasibility** (if applicable):
  - Infer tight **min/max** ranges for all involved variables from types, prior checks, and loop bounds.
  - Show whether overflow/underflow or OOB is actually triggerable (compute the smallest/largest values that violate constraints).

{{project_feasibility}}If there is any uncertainty in the classification, **err on the side of caution and classify it as a false positive**. Your analysis will be used to improve the static analyzer's accuracy.

{{input_patch}}

{{input_bug_pattern}}

# Report

{{input_bug_report}}

# Formatting

Please provide your answer in the following format:

- Decision: {Bug/NotABug}
- Reason: {Your reason here}
