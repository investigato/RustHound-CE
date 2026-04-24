```markdown
# RustHound-CE Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill provides guidance on contributing to the RustHound-CE codebase, a Rust project with a modular architecture. It covers the project's coding conventions, file organization, and key workflows—especially those involving cross-module refactoring or bugfixes. The guide also documents testing patterns and recommended commands for common development tasks.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `jsonParser.rs`, `apiClient.rs`

### Import Style
- Prefer **relative imports** within the crate.
  - Example:
    ```rust
    use crate::objects::userObject;
    use super::parserUtils;
    ```

### Export Style
- Use **named exports** for modules and items.
  - Example:
    ```rust
    pub mod jsonParser;
    pub struct UserObject { ... }
    pub enum ParseError { ... }
    ```

### Commit Patterns
- Commit messages are **freeform** (no strict prefix), average length ~46 characters.
  - Example: `Fix enum variant parsing in jsonParser`

## Workflows

### Cross-Module Refactor or Bugfix
**Trigger:** When a change (bugfix, refactor, schema update, etc.) affects multiple related modules, such as enums, objects, and parsers.
**Command:** `/cross-module-refactor`

1. **Identify the cross-cutting concern**
   - Example: A parsing bug, schema mismatch, or naming inconsistency.
2. **Update enums**
   - Modify relevant enums in `src/enums/*.rs` to reflect new or corrected values/types.
     ```rust
     // src/enums/statusEnum.rs
     pub enum Status {
         Active,
         Inactive,
         Suspended, // New variant added
     }
     ```
3. **Modify parser modules**
   - Update logic in `src/json/parser/mod.rs` to handle the new or corrected enum/object structure.
     ```rust
     // src/json/parser/mod.rs
     match status_str {
         "active" => Status::Active,
         "inactive" => Status::Inactive,
         "suspended" => Status::Suspended,
         _ => return Err(ParseError::UnknownStatus),
     }
     ```
4. **Update object definitions and related modules**
   - Adjust structs and related logic in `src/objects/*.rs` and other modules as needed.
     ```rust
     // src/objects/userObject.rs
     pub struct User {
         pub status: Status,
         // ...
     }
     ```
5. **Adjust API layer if exposed externally**
   - Update `src/api.rs` to reflect changes in data structures or endpoints.
6. **Test changes across affected modules**
   - Run or write tests to ensure the changes are correct and do not break other functionality.

**Files Involved:**
- `src/enums/*.rs`
- `src/json/parser/mod.rs`
- `src/objects/*.rs`
- `src/api.rs`
- `src/modules/**/*.rs`

**Frequency:** ~2 times per month

## Testing Patterns

- **Framework:** Unknown (not detected in analysis)
- **File Pattern:** Test files are named with the pattern `*.test.*`
  - Example: `userObject.test.rs`, `parserUtils.test.rs`
- **Test Example:**
  ```rust
  // userObject.test.rs
  #[cfg(test)]
  mod tests {
      use super::*;

      #[test]
      fn test_user_status_parsing() {
          // ...test logic...
      }
  }
  ```

## Commands

| Command                | Purpose                                                         |
|------------------------|-----------------------------------------------------------------|
| /cross-module-refactor | Initiate a coordinated refactor or bugfix across multiple modules|
```
