# Resuming Work

This is the first thing to read in a new session. It takes a few minutes to get
back to a known-good state.

## 1. Read where we are

- `plans/parity.md` — start at the **Where we are** block. It names the current
  focus, the ordered "Next up" list, per-area status, any scoping notes or
  gotchas, plus the last commit and current gate results. Do not re-derive state
  from git history.
- `plans/inventory/python_port_inventory.tsv` — the per-symbol ledger
  (status + `crystal_refs`). Use it to see what is left inside the current
  chunk:

  ```bash
  tail -n +2 plans/inventory/python_port_inventory.tsv \
    | cut -f3 | sort | uniq -c
  ```

  Update `plans/inventory/python_source_parity.tsv` and
  `plans/inventory/python_test_parity.tsv` when source or test coverage changes.

## 2. Confirm the working tree

```bash
git log --oneline -10
git status
```

The last commit should be the previous feature, committed atomically. If the
tree is dirty, finish or stash before starting.

## 3. Confirm a clean baseline

```bash
make format-check
make lint
make test
```

All must pass before changing anything. `make build` should also succeed.

## 4. Pick the next feature

Take the first unchecked item in the **Next up** list (or the next `[ ]` item in
the current phase). For each feature:

1. Read the upstream source under `vendor/python-keyring` and the nearest
   upstream tests.
2. Port the tests first (red → green); never weaken assertions.
3. Satisfy the **Definition of done** in `CLAUDE.md`/`AGENTS.md` (API, tests,
   gates, inventory rows, `plans/parity.md` status + **Where we are** refresh,
   divergences).
4. Commit atomically using the `port: ...` message format from
   `CLAUDE.md`/`AGENTS.md`.

## If the plan is split

When `plans/parity.md` grows too large it is split into `plans/<area>.md` files.
In that case every split file is linked from `plans/parity.md`, and
`plans/parity.md` marks each file complete/in-progress and names the file being
worked on plus the next file/phase to start.

## Environment notes

- `vendor/python-keyring` is a git submodule pinned to Python keyring v25.7.0
  (commit `38c0401`). Run `git submodule update --init --recursive` after a
  fresh clone.
- Linux Secret Service/KWallet specs need D-Bus. Run them in the container:

  ```bash
  make docker-build
  make test-linux
  ```

- Keep scratch output under `./temp`; `make clean` removes it along with build
  artifacts.
