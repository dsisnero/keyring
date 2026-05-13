# Development Guide

## Setup

```bash
git clone --recurse-submodules https://github.com/dsisnero/keyring
cd keyring
make install      # shards install
```

## Daily Workflow

1. Check for ready work: `bd ready --json`
2. Claim a task: `bd update <id> --status in_progress --json`
3. Implement with tests
4. Run quality gates:
   ```bash
   make format-check    # crystal tool format --check
   make lint            # ameba
   make test            # crystal spec
   ```
5. Close issue: `bd close <id> --reason "Done" --json`
6. Commit code + `.beads/issues.jsonl` together
7. Push

## Porting from Python

When porting upstream Python code:
1. Find corresponding file in `vendor/python-keyring/keyring/`
2. Preserve exact behavior (parameter order, edge cases, error types)
3. Port upstream tests into `spec/` as Crystal specs
4. Use the language mapping in `CLAUDE.md` for translation
5. Document any unavoidable deviations in `docs/deviations.md`

## Platform-Specific Development

### macOS
- Native development; macOS backend tests run directly
- Keychain permission dialogs may appear; see README.md for solutions

### Linux
- Use containers: `make docker-build && make test-linux`

### Windows
- Requires win32cr shard; tests run natively on Windows
