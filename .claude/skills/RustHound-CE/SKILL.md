```markdown
# RustHound-CE Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill introduces the core development patterns and workflows used in the RustHound-CE codebase, a Rust project focused on directory enumeration and analysis. It covers coding conventions, file organization, and the main workflow for adding or updating enum and object types, which is central to extending the application's capabilities.

## Coding Conventions

### File Naming
- **Convention:** camelCase
- **Example:** `userAccount.rs`, `delegatedMsa.rs`

### Import Style
- **Convention:** Relative imports are used within modules.
- **Example:**
    ```rust
    use crate::enums::acl::AclType;
    use super::attribute::Attribute;
    ```

### Export Style
- **Convention:** Named exports (using `pub`).
- **Example:**
    ```rust
    pub struct User {
        pub name: String,
        pub email: Option<String>,
    }

    pub enum LdapType {
        User,
        Group,
        Computer,
    }
    ```

## Workflows

### Add or Update Enum and Object Type
**Trigger:** When you need to introduce a new type or extend enum/object definitions (e.g., for new account types or features).  
**Command:** `/add-type`

1. **Edit or add enum files** in `src/enums/`
    - Example: Add a new variant to `src/enums/ldaptype.rs`
        ```rust
        pub enum LdapType {
            User,
            Group,
            Computer,
            ServiceAccount, // new variant
        }
        ```
2. **Edit or add object files** in `src/objects/`
    - Example: Add a new struct in `src/objects/delegatedmsa.rs`
        ```rust
        pub struct DelegatedMsa {
            pub id: String,
            pub permissions: Vec<String>,
        }
        ```
3. **Update related API logic** in `src/api.rs` if needed
    - Example: Handle the new type in an API function
        ```rust
        match ldap_type {
            LdapType::ServiceAccount => handle_service_account(),
            _ => { /* existing logic */ }
        }
        ```
4. **Test your changes** (see Testing Patterns below).

**Files Involved:**
- `src/enums/acl.rs`
- `src/enums/ldaptype.rs`
- `src/enums/constants.rs`
- `src/enums/schema_guids.rs`
- `src/objects/user.rs`
- `src/objects/delegatedmsa.rs`
- `src/objects/attribute.rs`
- `src/api.rs`

## Testing Patterns

- **Test File Pattern:** `*.test.*` (e.g., `user.test.rs`)
- **Framework:** Not explicitly specified; likely uses Rust's built-in test framework.
- **Example:**
    ```rust
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_user_creation() {
            let user = User { name: "Alice".into(), email: None };
            assert_eq!(user.name, "Alice");
        }
    }
    ```

## Commands

| Command    | Purpose                                                        |
|------------|----------------------------------------------------------------|
| /add-type  | Add or update enum/object types to support new features/types. |
```
