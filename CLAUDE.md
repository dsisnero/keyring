# Keyring (Crystal)

> **How to resume:** read `plans/parity.md` first and use its **Where we are**
> block (current focus + ordered "Next up"), then run `make lint` and
> `make test`. Details: [docs/resuming.md](docs/resuming.md). Do not re-derive
> state from git.

Crystal port of the Python [keyring](https://github.com/jaraco/keyring)
library (v25.7.0), vendored at `vendor/python-keyring` (commit `38c0401`).
Cross-platform secure password/secret storage — macOS Keychain, Windows
Credential Manager, Linux Secret Service/KWallet, and an encrypted file
fallback.

## Verified Commands

```bash
# Install/update dependencies
make install
make update

# Build
make build

# Test (all specs)
make test

# Test single backend
crystal spec spec/keyring/file_backend_spec.cr
crystal spec spec/keyring/macos_backend_spec.cr

# Code quality
make format-check   # crystal tool format --check src spec
make lint           # ameba (--fail-level Error)
```

## Documentation

| Doc | Contents |
|---|---|
| `README.md` | Project overview, features, installation, usage, CLI, config, contributing |
| `docs/resuming.md` | Start-of-session checklist and how to pick up parity work |
| `docs/architecture.md` | Module and backend overview, selection logic, encryption |
| `docs/development.md` | Environment setup, toolchain, platform-specific dev |
| `docs/coding-guidelines.md` | Crystal style, naming, lint rules |
| `docs/testing.md` | Spec conventions, backend contract tests, test structure |
| `docs/pr-workflow.md` | Branch, commit, review process |
| `docs/deviations.md` | Intentional differences from upstream Python |
| `plans/parity.md` | Feature parity checklist vs Python v25.7.0 |
| `plans/inventory/` | Source and test parity manifests (TSV) |

## Core Principles

1. **Upstream behavior is source of truth.** `vendor/python-keyring` wins over
   local preference; preserve Python API semantics, parameter order, and error
   behavior exactly. Express in Crystal idioms.
2. **Port behavior, not style.**
3. **Port tests first.** Every feature needs a spec before implementation;
   never weaken upstream assertions.
4. **Cross-platform correctness.** Compile-time flags for darwin/linux/windows
   backends; fallback always available.
5. **Minimal dependencies.** Sodium for encryption; platform-native APIs for
   backend integration.
6. **Track parity.** Keep `plans/parity.md` and `plans/inventory/` current.
7. **Verify continuously.** Run quality gates after every change.

## Session continuity (read this first)

`plans/parity.md` is the single source of truth for where we are. At the start
of every session:

1. Read `plans/parity.md` and use its **Where we are** block to find the current
   focus, the ordered "Next up" list, and per-area status. Do not re-derive state
   from git history.
2. Skim `git log --oneline -10` and `git status` to confirm the working tree.
3. Run `make lint` and `make test` before changes to confirm a clean baseline.

See [docs/resuming.md](docs/resuming.md) for the full resume checklist.

### Keeping `plans/parity.md` resumable

- `plans/parity.md` starts with a **Where we are** block (`Current focus`,
  `Next up`, status by area, last commit, gate results). Keep it accurate after
  every feature.
- Work items are feature-sized (roughly one branch/commit). Per-symbol state
  lives in `plans/inventory/python_port_inventory.tsv`, not in the plan.
- If the plan grows too large, split it into `plans/<area>.md` files, link each
  from `plans/parity.md`, and mark each split file complete/in-progress plus the
  file being worked on next.

### Definition of done for every feature (required)

A feature is complete only when all of the following are true, and all of it
must be committed as **one** atomic commit before starting the next feature:

1. the API surface is implemented;
2. upstream tests (or equivalent characterization specs) exist and pass;
3. gates pass: `make format-check`, `make lint`, `make test`, and
   `make build`;
4. parity inventory rows for the feature are updated
   (`plans/inventory/python_port_inventory.tsv`, plus the source/test manifests
   when they change);
5. `plans/parity.md` status is updated and the **Where we are** block refreshed
   (current focus + next up);
6. any intentional divergence is documented in `docs/deviations.md` and/or the
   commit message.

### Commit message

For upstream parity work, start with `port:` and a one-line feature name, then
bullets for what changed, then the upstream revision
(`jaraco/keyring v25.7.0 (38c0401)`). Include new/changed files, divergences,
and gate results so a new session can resume from the commit alone.

For non-parity maintenance, use conventional commits: `<type>: <description>`
with types `feat`, `fix`, `test`, `refactor`, `docs`, `chore`.

## Project Conventions

- Crystal code under `src/`, specs under `spec/` (mirroring source structure).
- Backend abstract class in `src/keyring/backend.cr` defines the contract.
- Backends auto-register via `Backend.register(self)` at load time (`backend.cr`).
- All backends implement `get_password`, `set_password`, `delete_password`,
  `get_credential`, `list_credentials`.
- Platform backends loaded via `{% if flag?(:darwin) %}` etc. in `src/keyring.cr`;
  loaded before generic fallbacks for correct priority ordering.
- Backend registry (`Backend.registry`) provides discovery; `get_all_keyring`
  filters by viability.
- Encryption via Sodium SecretBox/XSalsa20-Poly1305, hashing via Argon2.
- Config is YAML (`config.yml`) with `KEYRING_*` env var overrides.
- Temporary files belong in `./temp/` (gitignored, excluded from lint).
