# Coding Standards

## Crystal Style

- 2-space indent, LF line endings, UTF-8, trailing newline
- `snake_case` for methods/variables, `PascalCase` for classes/modules
- Explicit type annotations for method parameters and return types
- See `.editorconfig` for full settings

## Formatting & Linting

```bash
make format        # crystal tool format
make format-check  # crystal tool format --check
make lint          # ameba
make pre-commit    # format-check + lint
```

## Naming

| Element | Convention | Example |
|---|---|---|
| Modules | `PascalCase` | `Keyring::LinuxBackend` |
| Classes | `PascalCase` | `class FileBackend` |
| Methods | `snake_case` | `def get_password` |
| Variables | `snake_case` | `keyring_instance` |
| Constants | `UPPER_SNAKE_CASE` | `DEFAULT_SERVICE` |
| Files | `snake_case` | `linux_backend.cr` |

## Porting-Specific Rules

1. Do NOT change upstream behavior to be "more idiomatic"
2. Preserve exact parameter order, edge cases, and error types
3. Use `Bytes` for binary data (not `String`)
4. Use explicit numeric widths (`_u8`, `_i32`) where signedness/range matters
5. Preserve boundary semantics exactly (e.g., half-open ranges)

## Dependencies

Add new dependencies to `shard.yml` only when required for parity with upstream behavior. Prefer the standard library when possible.
