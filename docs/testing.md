# Testing Guide

## Running Tests

```bash
crystal spec                    # All tests
crystal spec spec/path/to/file  # Single file
make test                       # All tests (alias)
make test-macos                 # macOS backend only
make test-file                  # File backend only
```

## Linux Backend Testing

Linux backend tests require a container environment:

```bash
make docker-build    # Build container image
make test-linux      # Run Linux backend tests in container
make docker-dev      # Interactive shell in container
```

Inside container: `with-keyring crystal spec`

## Test Conventions

- Spec files mirror upstream test files: `test_backend.py` → `backend_spec.cr`
- Fixtures must match upstream expectations exactly
- Use characterization specs when upstream lacks tests (mark with comment)
- Platform-specific tests use `pending` when not applicable to current OS
- Do NOT weaken assertions or skip branches from upstream tests

## Test Structure

```
spec/
  ├── keyring/         # Unit/contract specs per module
  ├── integration/     # Integration tests
  ├── support/         # Test helpers and shared contexts
  ├── spec_helper.cr   # Common spec configuration
  └── README.md        # Test documentation
```
