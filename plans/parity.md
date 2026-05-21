# Parity Plan: Python keyring v25.7.0 → Crystal

Source of truth: `vendor/python-keyring` (submodule, tag v25.7.0)

## Core API

- [x] `get_password(service, username)` — module-level + CLI get command
- [x] `set_password(service, username, password)` — module-level + CLI set command
- [x] `delete_password(service, username)` — module-level + CLI delete command
- [x] `get_credential(service, username)` — module-level + CLI get --mode creds
- [x] `set_keyring(backend)` / `get_keyring()` — module-level backend getter/setter
- [x] `list_credentials` — Crystal extension (upstream has no equivalent)
- [x] `list_services` / `list_usernames(service)` — Crystal extension
- [x] `search(query)` / `advanced_search` — Crystal extension
- [x] `disable()` — configure null keyring as default via config file write

## Backend System

- [x] `Backend` abstract class with `get_password`, `set_password`, `delete_password`, `get_credential`
- [x] `MacOSBackend` — macOS Keychain via Security.framework C API
- [x] `WindowsBackend` — Windows Credential Manager via win32cr
- [x] `LinuxSecretServiceBackend` — Linux Secret Service via libsecret D-Bus
- [x] `KWalletBackend` — KDE KWallet5 via qdbus CLI (upstream uses dbus-python)
- [x] KDE KWallet4 backend variant (`DBusKeyringKWallet4`) — separate bus/object path
- [x] `ChainerBackend` — iterate multiple backends for reads, try writes on each
- [x] `NullBackend` — no-op backend
- [x] `FailBackend` — always raises
- [x] `FileBackend` — Crystal-specific encrypted JSON file storage
- [x] Backend plugin/registration system (`_load_plugins`, `get_all_keyring`) — Crystal compile-time requires with `Backend.register`/`Backend.registry` class-level registration; `_load_plugins` is a no-op (compile-time requires handle loading)
- [x] `_detect_backend(limit)` — backend detection with caller-supplied filter
- [x] `load_keyring(keyring_name)` — load backend by fully-qualified name
- [x] `load_env()` — load backend from `PYTHON_KEYRING_BACKEND` env var (Crystal has `KEYRING_BACKEND` config env but not module import)
- [x] `load_config()` — load backend from keyringrc.cfg (Crystal config.yml has `preferred_backend` but not full dynamic loading)
- [x] `by_priority` / `_limit` — backend filtering and priority-based sorting helpers
- [x] `recommended(backend)` — check if backend priority >= 1
- [x] `KeyringBackendMeta` metaclass — auto-registration via `Backend.register(self)` in each backend class; username validation not needed (Crystal type system enforces non-empty strings at compile time)

## Backend Features (upstream)

- [x] `priority` class property — each backend declares a priority score
- [x] `available?` class method — viability check (returns Bool, Crystal extension)
- [x] `viable` class property — upstream wraps priority in exception trap (Crystal uses `available?`)
- [x] `name` class property — display name derived from module/class (Crystal uses `display_name`)
- [x] `set_properties_from_env()` — set backend properties from `KEYRING_PROPERTY_*` env vars
- [x] `with_properties(**kwargs)` — clone backend with overridden properties
- [x] Backend health check — lightweight validation on init
- [x] Backend failover — auto-switch to next viable backend on persistent failure
- [x] `supports_metadata?` / `set_metadata` — optional per-backend metadata storage

## CLI

- [x] `get` command — retrieve password (supports plain/json output)
- [x] `set` command — store password (interactive or stdin pipe)
- [x] `delete` command — delete password (with optional --confirm)
- [x] `list` command — list all credentials (plain/json)
- [x] `search` command — search by query string
- [x] `export` / `import` commands — bulk credential export/import (JSON)
- [x] `config` command — show/set configuration
- [x] `backend` command — list/switch backends at runtime
- [x] `generate-key` command — generate a Sodium encryption key
- [x] `completion` command — generate bash/zsh shell completion scripts
- [x] `update` command — update existing credential's password
- [x] `diagnose` command — show config path and data root path
- [x] `--list-backends` flag — print all available backends and exit
- [x] `--disable` flag — disable keyring and exit (calls `disable()`)
- [x] `--keyring-backend` flag — specify backend by name to use
- [x] `--print-completion` flag — print shell completion script (upstream uses shtab)
- [x] Dynamic backend completion (tab-complete available backend names for --keyring-backend)
- [x] `--mode creds` returns both username + password on separate lines

## Credentials

- [x] `Credential` struct — service, username, password, metadata, timestamps
- [x] Password encryption/decryption via Sodium SecretBox
- [x] `add_metadata(key, value)` / `remove_metadata(key)`
- [x] `SchemeSelectable` — backend base class for alternate attribute schemes (KeePassXC)
- [x] `SimpleCredential` — Crystal `Credential` struct with optional password covers both Simple and Anonymous cases
- [x] `AnonymousCredential` — username-less credential for get --mode creds
- [x] `EnvironCredential` — credentials sourced from environment variables

## Configuration

- [x] YAML-based config (`config.yml`) with env var overrides
- [x] `preferred_backend` — explicit backend selection
- [x] `backend_priority` — ordered backend preference list
- [x] `encrypt_passwords` — toggle password encryption
- [x] `log_level` / `log_file` — logging configuration
- [x] `default_service` — optional default service name
- [x] `set_property(key, value)` / `save` — programmatic config mutation
- [x] Backend discovery from config file with keyring-path support (upstream: `load_config` + `_load_keyring_path`)

## Encryption

- [x] Sodium SecretBox (XSalsa20-Poly1305) encrypt/decrypt
- [x] Argon2 password hashing and verification
- [x] Secure random key generation
- [x] Secure random token generation
- [x] Secure random salt generation
- [x] `Crypter` abstract base class — encrypt/decrypt interface
- [x] `NullCrypter` — no-op crypter (passthrough)

## Error Handling

- [x] `KeyringError` — base exception
- [x] `InitError` — backend initialization failure
- [x] `PasswordSetError` — password storage failure
- [x] `PasswordDeleteError` — password deletion failure
- [x] `ConfigError` — configuration errors
- [x] `EncryptionError` — encryption/decryption failures
- [x] `CircuitOpenError` — circuit breaker tripped
- [x] `BackendError` — all backends unavailable
- [x] `KeyringLocked` — KWallet/SecretService keyring locked by user

## Reliability Features (Crystal Extensions)

- [x] Circuit breaker — open after 5 consecutive failures, half-open after timeout
- [x] Retry with exponential backoff — configurable retry policy
- [x] Backend failover — auto-switch on persistent failure
- [x] Operation metrics — success/failure/latency tracking per backend per operation
- [x] Metrics summary — debug-printable stats

## Tests

### Backend Contract Tests
- [x] `test_password_set_get` — basic set/get round-trip
- [x] `test_set_after_set_blank` — overwrite empty password
- [x] `test_difficult_chars` — whitespace + punctuation in values
- [x] `test_delete_present` — delete existing credential
- [x] `test_delete_not_present` — delete non-existent raises
- [x] `test_delete_one_in_group` — delete one user preserves others
- [x] `test_name_property` — backend name is ASCII printable
- [x] `test_unicode_chars` — Unicode (CJK, Hebrew, Greek, Cyrillic) in values
- [x] `test_unicode_and_ascii_chars` — mixed character sets
- [x] `test_different_user` — multiple users per service
- [x] `test_credential` — get_credential with/without username
- [x] `test_empty_username` — deprecated empty username still works
- [x] `test_set_properties` — KEYRING_PROPERTY_* env var parsing
- [x] `test_new_with_properties` — with_properties() clone behavior
- [x] `test_wrong_username_returns_none` — non-existent user returns nil

### Per-Backend Tests
- [x] macOS backend spec
- [x] Windows backend spec
- [x] Linux SecretService backend spec
- [x] KWallet backend spec
- [x] Chainer backend spec
- [x] libsecret backend spec (separate from SecretService) — Crystal consolidates SecretService + libsecret into single `LinuxSecretServiceBackend`; all tests in `linux_backend_spec.cr` (18 tests, 2 pending due to ARM64/GLib runtime)
- [x] Null/Fail backend spec
- [x] FileBackend spec
- [x] Encryption spec
- [x] Credential spec
- [x] Config spec
- [x] Platform spec
- [x] Circuit breaker spec
- [x] Retryable spec
- [x] Metrics spec
- [x] Reliability spec
- [x] Backend priority spec
- [x] Backend metadata spec

### CLI Tests
- [x] `test_set_interactive` — set password from interactive prompt
- [x] `test_set_pipe` — set password from stdin pipe
- [x] `test_set_pipe_newline` — strip trailing newline from pipe input
- [x] `test_get_anonymous` — get with --mode creds returns password-only credential
- [x] `test_get` — get with --mode creds returns username + password
- [x] `test_output_json` — JSON output format for get/list
- [x] `test_output_plain` — plain text output format
- [x] CLI error handling tests (missing args, invalid commands, backend load failures)

### Integration Tests
- [x] End-to-end spec (basic flow)
- [x] Multi-backend integration (chainer, failover scenarios)
- [x] Config persistence round-trip
- [x] Export/import round-trip integrity

## Module-Level API (Keyring.keyring class-level)

- [x] `Keyring.get_password(service, username)` — delegated shortcut
- [x] `Keyring.set_password(service, username, password)` — delegated shortcut
- [x] `Keyring.delete_password(service, username)` — delegated shortcut
- [x] `Keyring.get_credential(service, username)` — delegated shortcut
- [x] `Keyring.keyring=(backend)` — set singleton backend
- [x] `Keyring.keyring` — get/lazy-init singleton backend

## Intentionally Skipped (Not Applicable)

| Feature | Reason |
|---|---|
| `devpi_client` module | Python DevPI-specific, no Crystal equivalent |
| `http` module | Python HTTP backend, can be separate shard if needed |
| `compat.properties` / `compat.py312` | Python 2/3/3.12 compatibility shims |
| Setuptools entry points plugin loading | Crystal has no runtime plugin system; compile-time requires |
| `SimpleCredential` class | Crystal `Credential` struct covers both Simple and Anonymous use cases |
| `test_packaging`, `test_multiprocess` | Python packaging/multiprocess tests |
