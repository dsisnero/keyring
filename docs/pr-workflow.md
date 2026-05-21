# Pull Request Workflow

## Before Creating a PR

```bash
crystal spec                   # all 313 tests
make format-check              # crystal tool format --check src spec
make lint                      # ameba
shards build                   # verify compilation
```

## PR Checklist

- [ ] All tests pass locally
- [ ] Code is formatted (`crystal tool format --check src spec`)
- [ ] Lint passes (`make lint`)
- [ ] Project compiles (`shards build`)
- [ ] Upstream behavior is preserved (no semantic changes)
- [ ] New features have specs
- [ ] Deviations from upstream documented in `docs/deviations.md`

## Commit Messages

Conventional commits: `<type>: <description>`

Types: `feat`, `fix`, `test`, `refactor`, `docs`, `chore`

Examples:
```
feat: add backend registration system
fix: correct FILETIME field names for Windows
test: add contract tests for ChainerBackend
docs: update architecture diagram
```

## After Merge

1. Verify CI passes on main
2. Update `CHANGELOG.md` for user-facing changes (if present)
