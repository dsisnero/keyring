# Architecture

## Overview

This is a Crystal port of the Python [keyring](https://github.com/jaraco/keyring) library (v25.7.0), providing secure password/secret storage across different platforms.

## Design

All backends implement the abstract `Keyring::Backend` class, which defines the core API:

```
Keyring::Backend (abstract)
  ├── Keyring::MacOSBackend     — macOS Keychain via Security.framework C API
  ├── Keyring::LinuxBackend     — Linux Secret Service via libsecret
  ├── Keyring::WindowsBackend   — Windows Credential Manager via win32cr
  └── Keyring::FileBackend      — Encrypted JSON file storage (Sodium)
```

## Core Modules

| Module | File | Purpose |
|---|---|---|
| `Keyring::Backend` | `src/keyring/backend.cr` | Abstract base class for all backends |
| `Keyring::Keyring` | `src/keyring/keyring.cr` | Main API (get_password, set_password, delete_password) |
| `Keyring::Config` | `src/keyring/config.cr` | Configuration file management |
| `Keyring::Encryption` | `src/keyring/encryption.cr` | Password encryption (Sodium SecretBox, Argon2) |
| `Keyring::Credential` | `src/keyring/credential.cr` | Credential data structure |
| `Keyring::CLI` | `src/keyring/cli.cr` | Command-line interface |
| `Keyring::Errors` | `src/keyring/errors.cr` | Custom exception classes |
| `Keyring:🤚ogging` | `src/keyring/logging.cr` | Diagnostic logging |

## Backend Selection

Platform-specific backends are loaded at compile time via `{% if flag?(:darwin) %}`, etc. in `src/keyring.cr`. The `FileBackend` is always available as a universal fallback.

## Upstream Reference

- Source: `vendor/python-keyring` (submodule, tag v25.7.0)
- Main package: `vendor/python-keyring/keyring/`
