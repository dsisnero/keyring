# CLAUDE.md - Source of Truth Policy

## Source of Truth

**This repository is a Crystal port of the Python [keyring](https://github.com/jaraco/keyring) library.**

Upstream is vendored as a git submodule:
- Path: `vendor/python-keyring`
- Pinned ref: **v25.7.0** (commit `38c0401`)
- Repository: https://github.com/jaraco/keyring

**Upstream behavior is the source of truth.** Port behavior first, then express it with Crystal idioms. All deviations from upstream behavior must be documented with justification.

## Parity Policy

1. Every Crystal API surface must match upstream Python behavior (parameter order, edge cases, error types).
2. Upstream tests are normative specs - port them into Crystal specs without weakening assertions.
3. Fixtures and golden outputs must match upstream exactly.
4. Unavoidable language-level differences (e.g., Python's dynamic typing vs Crystal's static typing) must be documented in `docs/deviations.md`.

## Quick Reference

See [AGENTS.md](AGENTS.md) for commands, quality gates, and development workflow.

## Language Mapping (Python -> Crystal)

| Python | Crystal |
|---|---|
| `class Foo:` | `class Foo` |
| `def bar(self, x):` | `def bar(x : T) : R` |
| `None` | `nil` |
| `raise ValueError("msg")` | `raise ArgumentError.new("msg")` |
| `str` / `unicode` | `String` |
| `bytes` | `Bytes` |
| `dict` | `Hash(K, V)` |
| `list` | `Array(T)` |
| `tuple` | `Tuple(*T)` |
| `Optional[T]` | `T?` |
| `with` statement | `File.open(...) { |f| ... }` block form |
| `try/except` | `begin/rescue` |
| `*_test.py` | `*_spec.cr` |
| `unittest` / `pytest` | Crystal `spec` |
| `isinstance()` | `is_a?()` |
| `@property` | Crystal `getter` / `property` macro |
