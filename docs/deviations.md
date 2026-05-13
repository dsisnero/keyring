# Deviations from Upstream (Python keyring v25.7.0)

This document tracks intentional differences between this Crystal port and the upstream Python keyring library.

## Language-Level Differences

| Item | Python | Crystal | Reason |
|---|---|---|---|
| Dynamic typing | `dict`, flexible args | Static types, explicit type annotations | Crystal language requirement |
| `None` return | Methods return `None` for missing passwords | Return `nil` | Crystal equivalent |
| Dependencies | Runtime: `secretstorage`, `dbus-python`, `pywin32` | Compile-time: `win32cr`, `sodium` (dev) | Platform differences |
| Backend registration | Setuptools entry points | Compile-time `require` | Crystal has no runtime plugin system |
| `keyring.get_keyring()` | Returns current backend instance | No exact equivalent yet | Under consideration |

## Backend Differences

| Feature | Python | Crystal | Status |
|---|---|---|---|
| KDE KWallet | Supported via dbus-python | Not implemented | Linux backend uses Secret Service only |
| `keyrings.alt` compatibility | Supports alt backends | Not applicable | Crystal has its own FileBackend |
| Third-party backends | Setuptools entry points | Manual registration | Design TBD |

## Configuration Differences

- Python uses `keyringrc.cfg` (INI format); Crystal uses `config.yml` (YAML format)
- Python supports `PYTHON_KEYRING_BACKEND` env var; Crystal equivalent is config file only

## Unported Features

Refer to `plans/inventory/python_port_inventory.tsv` for the complete tracking of ported and unported features.

*Last updated: 2026-05-12 (pin: v25.7.0)*
