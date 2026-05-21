# Testing Guide

## Running Tests

```bash
crystal spec                     # All 313 tests
crystal spec spec/path/to/file   # Single file
make test                        # All tests (alias)

# Platform-specific
crystal spec spec/keyring/macos_backend_spec.cr
crystal spec spec/keyring/file_backend_spec.cr
crystal spec spec/keyring/chainer_backend_spec.cr
crystal spec spec/keyring/backend_registration_spec.cr
```

## Linux Backend Testing

Linux backend tests require a D-Bus session with GNOME Keyring or KWallet:

```bash
make docker-build                # Build container image
make test-linux                  # Run Linux backend tests in container
make docker-dev                  # Interactive shell in container
```

Inside container: `crystal spec spec/keyring/linux_backend_spec.cr`

## Test Convention

- Spec files mirror source structure: `src/keyring/foo.cr` → `spec/keyring/foo_spec.cr`
- Platform-specific tests use `{% if flag?(:linux) %}` and `pending` for non-applicable OS
- Backend contract tests live in `spec/keyring/backend_contract_spec.cr`
- Registration tests in `spec/keyring/backend_registration_spec.cr`

## Test Structure

```
spec/
  ├── keyring/              # Unit/contract specs per module
  │   ├── backend_contract_spec.cr
  │   ├── backend_metadata_spec.cr
  │   ├── backend_priority_spec.cr
  │   ├── backend_registration_spec.cr
  │   ├── chainer_backend_spec.cr
  │   ├── circuit_breaker_spec.cr
  │   ├── cli_spec.cr
  │   ├── config_spec.cr
  │   ├── credential_spec.cr
  │   ├── encryption_spec.cr
  │   ├── file_backend_spec.cr
  │   ├── kwallet_backend_spec.cr
  │   ├── linux_backend_spec.cr
  │   ├── macos_backend_spec.cr
  │   ├── metrics_spec.cr
  │   ├── null_fail_backend_spec.cr
  │   ├── platform_spec.cr
  │   ├── reliability_spec.cr
  │   ├── retryable_spec.cr
  │   ├── windows_backend_spec.cr
  │   └── keyring_spec.cr
  ├── integration/          # Integration tests
  │   └── end_to_end_spec.cr
  ├── spec_helper.cr        # Common spec configuration
  └── README.md             # Test documentation
```

## Pending Tests

13 tests are pending — all Linux-only backends (SecretService, KWallet) that require a D-Bus session not available in standard CI.
