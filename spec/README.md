# Keyring Test Suite

## Overview

This directory contains the comprehensive test suite for the keyring library. Tests are organized by component and include unit tests, integration tests, and backend contract tests.

## Test Structure

```
spec/
├── spec_helper.cr                 # Test configuration and shared utilities
├── keyring_spec.cr                # Main Keyring class tests
├── keyring/
│   ├── backend_contract_spec.cr   # Shared backend contract tests
│   ├── windows_backend_spec.cr    # Windows-specific tests
│   ├── linux_backend_spec.cr      # Linux-specific tests
│   ├── macos_backend_spec.cr      # macOS-specific tests
│   ├── file_backend_spec.cr       # File backend tests
│   ├── config_spec.cr             # Configuration tests
│   ├── credential_spec.cr         # Credential model tests
│   ├── encryption_spec.cr         # Encryption module tests
│   └── cli_spec.cr                # CLI tests
├── integration/
│   └── end_to_end_spec.cr         # End-to-end integration tests
└── support/
    ├── mock_backend.cr            # Mock backend for testing
    └── test_helpers.cr            # Shared test utilities
```

## Running Tests

### Run all tests
```bash
crystal spec
```

### Run specific test file
```bash
crystal spec spec/keyring/encryption_spec.cr
```

### Run with verbose output
```bash
crystal spec --verbose
```

### Run on specific platform
Tests automatically detect platform and skip platform-specific tests when not applicable.

## Test Categories

### 1. Unit Tests
Test individual classes and methods in isolation.

**Files**: All `*_spec.cr` files in `spec/keyring/`

**Coverage**:
- Encryption module
- Config system
- Credential model
- Individual backend implementations

### 2. Backend Contract Tests
Shared test examples that all backends must pass to ensure API compliance.

**File**: `spec/keyring/backend_contract_spec.cr`

**Tests**:
- Basic CRUD operations (get, set, delete)
- Credential listing
- Error handling
- Edge cases (unicode, special characters, long passwords)
- Concurrent access

### 3. Integration Tests
Test interactions between components and end-to-end workflows.

**File**: `spec/integration/end_to_end_spec.cr`

**Tests**:
- Full credential lifecycle
- Backend selection and fallback
- Import/export functionality
- Configuration loading
- Search functionality

### 4. CLI Tests
Test command-line interface functionality.

**File**: `spec/keyring/cli_spec.cr`

**Tests**:
- All CLI commands
- Error messages
- Output formatting
- Interactive features

## Platform-Specific Testing

Tests use Crystal's conditional compilation to run platform-specific code:

```crystal
{% if flag?(:windows) %}
  # Windows-specific tests
{% elsif flag?(:linux) %}
  # Linux-specific tests
{% elsif flag?(:darwin) %}
  # macOS-specific tests
{% end %}
```

### Windows Testing
- Requires Windows 7+ with Credential Manager
- Uses win32cr library
- Tests Windows API integration

### Linux Testing
- Requires GNOME Keyring or KWallet
- Requires libsecret library
- Tests Secret Service D-Bus API

### macOS Testing
- Requires macOS 10.9+
- Tests Keychain Services API
- Tests Security Framework integration

## Test Helpers

### Mock Backend
Use `MockBackend` for testing without requiring actual system backends:

```crystal
backend = MockBackend.new
backend.set_password("service", "user", "pass")
```

### Test Data
Common test data is defined in `spec/support/test_helpers.cr`:

```crystal
include TestHelpers

test_credential = create_test_credential
test_config = create_test_config
```

## Test Isolation

### Before/After Hooks
Each test cleans up after itself:

```crystal
before_each do
  # Clean up existing test credentials
end

after_each do
  # Remove test credentials
end
```

### Test Prefixes
Use consistent prefixes for test data to enable cleanup:
- Services: `test_*` or `*_test_*`
- Usernames: `test_*`
- Files: `/tmp/keyring_test_*`

## Coverage Goals

| Component | Target Coverage |
|-----------|----------------|
| Core API | >90% |
| Backends | >85% |
| Encryption | >95% |
| Config | >80% |
| CLI | >75% |
| Overall | >80% |

## Running Coverage Reports

```bash
# Install coverage tool
shards install

# Run with coverage
crystal spec --coverage

# View coverage report
open coverage/index.html
```

## Writing New Tests

### Test Template

```crystal
require "../spec_helper"

module Keyring
  describe MyNewClass do
    describe "#my_method" do
      it "does what it should" do
        obj = MyNewClass.new
        result = obj.my_method("input")
        result.should eq("expected")
      end

      it "handles errors" do
        obj = MyNewClass.new
        expect_raises(MyError) do
          obj.my_method("bad_input")
        end
      end
    end
  end
end
```

### Best Practices

1. **One assertion per test**: Keep tests focused
2. **Descriptive names**: Use clear test descriptions
3. **Clean up**: Always clean up test data
4. **Isolate**: Don't depend on other tests
5. **Fast**: Keep tests fast (<1s per test)
6. **Readable**: Make test intent clear

## Pending Tests

Tests marked with `pending` are placeholders for future implementation:

```crystal
pending "Implementation needed" do
  # Test code that will work once feature is implemented
end
```

Or just the description:

```crystal
it "does something not yet implemented"
```

## Debugging Tests

### Verbose output
```bash
crystal spec --verbose
```

### Run single test
```bash
crystal spec spec/keyring/encryption_spec.cr:42
```

### Add debug output
```crystal
it "debugs issue" do
  pp! variable  # Pretty print variable
  puts "Debug: #{value}"
  result = method_call
end
```

## CI/CD Integration

Tests run automatically on:
- Pull requests
- Commits to main branch
- Tagged releases

### GitHub Actions
See `.github/workflows/test.yml` for CI configuration.

Platforms tested:
- Ubuntu Latest (Linux)
- macOS Latest
- Windows Latest

## Contributing

When adding new features:
1. Write tests first (TDD)
2. Ensure all tests pass
3. Add integration tests for workflows
4. Update this README if adding new test categories
5. Aim for >80% coverage on new code

## Troubleshooting

### Tests hang
- Check for infinite loops
- Look for blocking I/O
- Add timeouts to long-running tests

### Tests fail intermittently
- Check for race conditions
- Ensure proper test isolation
- Look for timing-dependent assertions

### Platform-specific failures
- Verify platform requirements
- Check conditional compilation
- Test on actual platform, not just CI

## Resources

- [Crystal Spec Documentation](https://crystal-lang.org/reference/guides/testing.html)
- [Keyring Architecture](../docs/architecture.md)
- [Contributing Guide](../CONTRIBUTING.md)
