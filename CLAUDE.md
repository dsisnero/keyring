# Keyring (Crystal)

Crystal port of the Python [keyring](https://github.com/jaraco/keyring) library
(v25.7.0). Cross-platform secure password/secret storage — macOS Keychain,
Windows Credential Manager, Linux Secret Service/KWallet, and an encrypted
file fallback.

## Verified Commands

```bash
# Install/update dependencies
shards install
shards update

# Build
shards build

# Test (all specs)
crystal spec

# Test single backend
crystal spec spec/keyring/file_backend_spec.cr
crystal spec spec/keyring/macos_backend_spec.cr

# Code quality
crystal tool format --check src spec   # format check
shards build && crystal run lib/ameba/bin/ameba.cr -- --fail-level Error  # lint

# Linux backends (container)
make docker-build && make docker-test
make test-linux
```

## Quality Gates

| Gate | Command |
|---|---|
| Format | `crystal tool format --check src spec` |
| Lint | `make lint` |
| Specs | `crystal spec` |
| Build | `shards build` |

## Documentation

| Doc | Contents |
|---|---|
| `docs/architecture.md` | Module and backend overview |
| `docs/development.md` | Environment setup, toolchain |
| `docs/coding-guidelines.md` | Crystal style, naming, lint rules |
| `docs/testing.md` | Spec conventions, backend contract tests |
| `docs/pr-workflow.md` | Branch, commit, review process |
| `docs/deviations.md` | Intentional differences from upstream |
| `plans/parity.md` | Feature parity checklist vs Python v25.7.0 |
| `plans/inventory/` | Source and test parity manifests (TSV) |

## Core Principles

1. **Upstream behavior is source of truth.** Preserve Python API semantics,
   parameter order, and error behavior exactly. Express in Crystal idioms.
2. **Port tests first.** Every feature needs a spec before implementation.
3. **Cross-platform correctness.** Compile-time flags for darwin/linux/windows
   backends; fallback always available.
4. **Minimal dependencies.** Sodium for encryption; platform-native APIs for
   backend integration.
5. **Verify continuously.** Run quality gates after every change.

## Commit Convention

```
<type>: <description>
```

Types: `feat`, `fix`, `test`, `refactor`, `docs`, `chore`

## Project Conventions

- Crystal code under `src/`, specs under `spec/` (mirroring source structure).
- Backend abstract class in `src/keyring/backend.cr` defines the contract.
- All backends implement `Backend#get_password`, `set_password`,
  `delete_password`, `get_credential`, `list_credentials`.
- Platform backends loaded via `{% if flag?(:darwin) %}` etc. in
  `src/keyring/keyring.cr`.
- Encryption via Sodium SecretBox/XSalsa20-Poly1305, hashing via Argon2.
- Config is YAML (`config.yml`) with `KEYRING_*` env var overrides.
- Temporary files belong in `./temp/` (gitignored, excluded from lint).
