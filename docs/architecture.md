# Architecture

## Overview

Crystal port of [jaraco/keyring](https://github.com/jaraco/keyring) (Python v25.7.0). Provides secure password/secret storage across macOS Keychain, Windows Credential Manager, Linux Secret Service/KWallet, and an encrypted file fallback.

## Backend Hierarchy

All backends implement the abstract `Keyring::Backend` class. Backends auto-register via `Backend.register(self)` at load time. The registry (`Backend.registry`) is consulted for backend discovery and selection.

```
Keyring::Backend (abstract)
  ├── MacOsKeyChainBackend     — macOS Keychain via Security.framework C API
  ├── WindowsBackend           — Windows Credential Manager via win32cr
  ├── LinuxSecretServiceBackend — Linux Secret Service via libsecret + schema_shim.c
  ├── KWalletBackend           — KDE KWallet5 via qdbus CLI
  ├── KWallet4Backend          — KDE KWallet4 via qdbus CLI (separate bus path)
  ├── ChainerBackend           — Iterates all viable backends for reads; tries writes on each
  ├── FileBackend              — Encrypted JSON file storage (Sodium SecretBox, universal fallback)
  ├── NullBackend              — No-op (used by `keyring --disable`)
  └── FailBackend              — Always raises (last-resort when no backend available)
```

## Core Modules

| Module | File | Purpose |
|--------|------|---------|
| `Keyring::Backend` | `src/keyring/backend.cr` | Abstract class + registry (`register`, `registry`, `clear_registry`), `SchemeSelectable` mixin |
| `Keyring::Keyring` | `src/keyring/keyring.cr` | Main API — `get_password`, `set_password`, `delete_password`, `get_credential`, backend selection, failover, circuit breakers, retry |
| `Keyring::Config` | `src/keyring/config.cr` | YAML config (`config.yml`) with `KEYRING_*` env var overrides |
| `Keyring::Credential` | `src/keyring/credential.cr` | Credential struct with metadata, timestamps, serialization |
| `Keyring::Encryption` | `src/keyring/encryption.cr` | Sodium SecretBox encrypt/decrypt, Argon2 key derivation, `Crypter`/`NullCrypter` |
| `Keyring::CircuitBreaker` | `src/keyring/circuit_breaker.cr` | Trip after N consecutive failures, half-open recovery probe |
| `Keyring::Retryable` | `src/keyring/retryable.cr` | Configurable retry with exponential backoff |
| `Keyring::Metrics` | `src/keyring/metrics.cr` | Per-backend per-operation latency and success/failure tracking |
| `Keyring::Errors` | `src/keyring/errors.cr` | `KeyringError`, `PasswordSetError`, `PasswordDeleteError`, `InitError`, `CircuitOpenError`, `BackendError`, `KeyringLocked` |
| `Keyring::Logging` | `src/keyring/logging.cr` | Configurable diagnostic logging |
| `Keyring::Log` | `src/keyring/logging.cr` | Module-level log shortcut |
| `Keyring::CLI` | `src/keyring/cli.cr` | Command-line interface (Admiral-based) |
| `Keyring::Platform` | `src/keyring/platform.cr` | Platform-specific paths (config root, data root) |

## Backend Selection

1. **Env var**: `KEYRING_BACKEND` overrides all (set via `load_env`)
2. **Config file**: `preferred_backend` in `config.yml` (set via `load_config`)
3. **Auto-detect**: Highest-priority viable backend from the registry, filtered by `backend_priority` config order
4. **Fallback**: `FailBackend` (raises on every operation)

Platform-specific backends are loaded first via compile-time flags in `src/keyring.cr`, ensuring they register with higher priority than the generic fallbacks (`FileBackend`, `FailBackend`).

## Reliability Features

- **Circuit breaker** — opens after 5 consecutive failures; auto-closes after timeout
- **Retry with backoff** — configurable attempts, delay, and backoff multiplier
- **Backend failover** — auto-switches to next viable backend on persistent failure
- **Metrics** — latency and success/failure counts per backend per operation

## Platform Integration

### macOS (`src/keyring/macos_backend.cr`)
- Direct C API calls to Security.framework
- Keychain item management via `SecItemAdd`, `SecItemCopyMatching`, `SecItemDelete`
- Supports metadata via generic password attributes

### Windows (`src/keyring/windows_backend.cr`)
- Credential Manager API via win32cr shard
- Wraps `CredReadW`, `CredWriteW`, `CredDeleteW`, `CredEnumerateW`
- Compile-time guarded (`{% if flag?(:windows) %}`)
- Compat module (`compat.cr`) provides LibC type aliases and LibWin32 forwarding

### Linux (`src/keyring/linux_backend.cr`)
- libsecret C API via `schema_shim.c` (non-variadic ARM64 workaround)
- Links against `libsecret-1`, `glib-2.0` at compile time
- Separate `kwallet_backend.cr` for KDE KWallet5/4 via qdbus CLI
- Docker-based CI testing with D-Bus session + GNOME Keyring or KWallet daemon

## Encryption (FileBackend)

- **Encryption**: Sodium SecretBox (XSalsa20-Poly1305)
- **Key derivation**: Argon2id with random salt
- **Storage**: Encrypted JSON file (`credentials.enc.json`)
- **Features**: Optional password encryption, secure key generation, token generation, salt generation
- **Crypter interface**: `Encryption.encrypt(value, key)` / `Encryption.decrypt(encrypted, key)`

## Upstream Reference

- Source: `vendor/python-keyring` (git submodule, tag v25.7.0)
- Main package: `vendor/python-keyring/keyring/`
