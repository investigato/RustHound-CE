---
name: cross-module-refactor-or-bugfix
description: Workflow command scaffold for cross-module-refactor-or-bugfix in RustHound-CE.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /cross-module-refactor-or-bugfix

Use this workflow when working on **cross-module-refactor-or-bugfix** in `RustHound-CE`.

## Goal

A workflow for refactoring or fixing bugs that require coordinated changes across multiple related modules, enums, objects, and parsers.

## Common Files

- `src/enums/*.rs`
- `src/json/parser/mod.rs`
- `src/objects/*.rs`
- `src/api.rs`
- `src/modules/**/*.rs`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Identify the cross-cutting concern (e.g., parsing bug, schema update, naming fix).
- Update enums to reflect new or fixed values/types.
- Modify parser modules to handle the new or corrected logic.
- Update object definitions and related modules.
- Adjust API layer if exposed externally.

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.