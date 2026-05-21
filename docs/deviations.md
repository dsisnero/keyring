# Deviations from Upstream (Python keyring v25.7.0)

Intentional differences between this Crystal port and the upstream Python keyring library.

## Language-Level Differences

| Item | Python | Crystal | Reason |
|---|---|---|---|
| Dynamic typing | `dict`, flexible args | Static types, explicit annotations | Language requirement |
| `None` return | `None` for missing passwords | `nil` | Crystal equivalent |
| Runtime plugin system | Setuptools entry points | Compile-time `require` + `Backend.register` | Crystal has no runtime plugin system |
| Metaclass registration | `KeyringBackendMeta.__init__` hooks class creation | `Backend.register(self)` called at class body | No metaclasses in Crystal |
| `get_all_keyring()` | Entry points + import detection | `Backend.registry` populated at require time | Compile-time vs runtime |
| `KeyringBackendMeta` | Wraps `set_password` for username validation | Crystal type system enforces non-empty strings | Compile-time validation |
| `properties.classproperty` | pip library | Standard `def self.method` | No external dependency needed |
| `jaraco.functools.once` | pip library | Manual memoization or laziness | Minimal deps |
| Exception hierarchy | Python `Exception` subclasses | Crystal `Exception` subclasses | Crystal equivalent |

## Backend Differences

| Feature | Python | Crystal | Status |
|---|---|---|---|
| macOS Keychain | Security.framework via ctypes | Security.framework via direct C bindings | ✅ |
| Windows Credential Manager | pywin32 / pywin32-ctypes | win32cr shard (dsisnero fork) | ✅ |
| Secret Service (Freedesktop) | secretstorage library (Python) | libsecret C API via `schema_shim.c` | ✅ |
| KDE KWallet5 | dbus-python | qdbus CLI subprocess | ✅ |
| KDE KWallet4 | dbus-python | qdbus CLI subprocess (separate bus path) | ✅ |
| GI/libsecret | gi.repository.Secret (GObject) | Direct libsecret C API (same library) | ✅ |
| ChainerBackend | Iterates `get_all_keyring()` | Same logic, uses `Backend.registry` | ✅ |
| Crypto (encrypted backends) | `cryptography` or `keyrings.alt` | `Sodium::SecretBox` via sodium shard | ✅ |
| `keyrings.alt` compatibility | Supports alt backends | Not applicable; FileBackend is built-in | — |
| Third-party backends | Entry points | Manual registration via `Backend.register` | — |

## Configuration Differences

| Item | Python | Crystal |
|---|---|---|
| Format | INI (`keyringrc.cfg`) | YAML (`config.yml`) |
| Env var prefix | `PYTHON_KEYRING_BACKEND` | `KEYRING_BACKEND` |
| Property env vars | `KEYRING_PROPERTY_{NAME}` | `KEYRING_PROPERTY_{NAME}` (same) |
| Encrypt flag | `KEYRING_ENCRYPT` env var | `KEYRING_ENCRYPT` env var (same) |
| Config root (Linux) | `~/.config/python_keyring/` | `~/.config/keyring_cr/` |
| Data root (Linux) | `~/.local/share/python_keyring/` | `~/.local/share/keyring_cr/` |
| Config root (macOS) | Same as Linux | `~/.config/keyring_cr/` |
| Config root (Windows) | `%LOCALAPPDATA%\Python Keyring\` | `%APPDATA%\keyring_cr\` |

## Unported Features

| Feature | Reason |
|---|---|
| `http.PasswordMgr` (`urllib2` integration) | Python-specific; Crystal HTTP clients differ |
| `devpi_client` module | DevPI-specific (Python package index) |
| `compat.properties` / `compat.py312` | Python 2/3/3.12 compatibility shims |
| `test_packaging`, `test_multiprocess` | Python packaging/multiprocess tests |

*Last updated: 2026-05-21*
