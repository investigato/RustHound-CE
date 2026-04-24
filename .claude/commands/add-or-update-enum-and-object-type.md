---
name: add-or-update-enum-and-object-type
description: Workflow command scaffold for add-or-update-enum-and-object-type in RustHound-CE.
allowed_tools: ["Bash", "Read", "Write", "Grep", "Glob"]
---

# /add-or-update-enum-and-object-type

Use this workflow when working on **add-or-update-enum-and-object-type** in `RustHound-CE`.

## Goal

Adds or updates enum definitions and object types, often to support new features or account types.

## Common Files

- `src/enums/acl.rs`
- `src/enums/ldaptype.rs`
- `src/enums/constants.rs`
- `src/enums/schema_guids.rs`
- `src/objects/user.rs`
- `src/objects/delegatedmsa.rs`

## Suggested Sequence

1. Understand the current state and failure mode before editing.
2. Make the smallest coherent change that satisfies the workflow goal.
3. Run the most relevant verification for touched files.
4. Summarize what changed and what still needs review.

## Typical Commit Signals

- Edit or add enum files in src/enums/ (such as acl.rs, ldaptype.rs, constants.rs, schema_guids.rs)
- Edit or add object files in src/objects/ (such as user.rs, delegatedmsa.rs, attribute.rs)
- Update related API logic in src/api.rs if needed

## Notes

- Treat this as a scaffold, not a hard-coded script.
- Update the command if the workflow evolves materially.