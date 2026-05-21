# Development Guide

## Setup

```bash
git clone --recurse-submodules https://github.com/dsisnero/keyring
cd keyring
shards install
```

## Prerequisites

- Crystal >= 1.15.0
- libsodium (system package or vcpkg on Windows)
- Linux only: libsecret-1-dev, libglib2.0-dev

## Daily Workflow

1. Make changes with tests
2. Run quality gates:
   ```bash
   crystal spec              # all 313 tests
   make format-check         # crystal tool format --check src spec
   make lint                 # ameba
   shards build              # verify compilation
   ```
3. Commit with conventional commit messages

## Quality Gates

| Gate | Command |
|---|---|
| Tests | `crystal spec` |
| Format | `crystal tool format --check src spec` |
| Lint | `make lint` |
| Build | `shards build` |

## Porting from Python

When porting upstream Python code:

1. Find corresponding file in `vendor/python-keyring/keyring/`
2. Preserve exact behavior (parameter order, edge cases, error types)
3. Port upstream tests into `spec/` as Crystal specs
4. Document intentional deviations in `docs/deviations.md`

## Platform-Specific Development

### macOS

- Native development; macOS backend tests run directly
- Keychain permission dialogs may appear; see README.md for solutions
- Run only macOS specs: `crystal spec spec/keyring/macos_backend_spec.cr`

### Linux

- Linux backend specs excluded from CI matrix (require D-Bus)
- Use containers: `make docker-build && make test-linux`
- Run only file backend: `crystal spec spec/keyring/file_backend_spec.cr`

### Windows

- Requires win32cr shard (dsisnero fork)
- Windows backend compiles only on Windows (`{% if flag?(:windows) %}`)
- Build/test on a Windows machine or CI
