# Pull Request Workflow

## Before Creating a PR

1. Run quality gates:
   ```bash
   make pre-commit    # format + lint
   make test          # all tests
   shards build       # ensure compilation
   ```

2. Update parity inventory if porting upstream code:
   - Run `cross-language-crystal-parity` drift checks
   - Update `plans/inventory/python_port_inventory.tsv` statuses

3. Self-review using `forge-reflect-pr` skill

## PR Checklist

- [ ] All tests pass locally (and on your platform)
- [ ] Code is formatted (`crystal tool format --check`)
- [ ] Linting passes (`ameba`)
- [ ] Project compiles (`shards build`)
- [ ] Upstream behavior is preserved (no semantic changes)
- [ ] Tests are ported from upstream where applicable
- [ ] Deviations from upstream documented in `docs/deviations.md`
- [ ] `.beads/issues.jsonl` updated with issue closures
- [ ] PR references the bd issue(s) it resolves

## Commit Messages

Follow existing project style: concise, imperative mood, referencing bd issue IDs.

```
Implement X feature from upstream

Ports the Y module from python-keyring v25.7.0.
All upstream tests pass with equivalent Crystal specs.

Closes: keyring-xxx
```

## After Merge

1. Close related bd issues
2. Run `bd sync`
3. Update `CHANGELOG.md` if user-facing changes
