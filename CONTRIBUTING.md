# Contributing to Keyring

Thank you for your interest in contributing to the Keyring Crystal library! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and considerate of others when contributing to this project.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in the [issues](https://github.com/dsisnero/keyring/issues)
2. If not, create a new issue with:
   - A clear, descriptive title
   - Steps to reproduce the bug
   - Expected behavior
   - Actual behavior
   - Environment details (OS, Crystal version, etc.)
   - Any relevant logs or error messages

### Requesting Features

1. Check if the feature has already been requested
2. If not, create a new issue with:
   - A clear, descriptive title
   - Detailed description of the feature
   - Use cases and benefits
   - Any implementation ideas or references

### Contributing Code

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Make your changes**
4. **Run tests**: Ensure all tests pass with `crystal spec` or `make test`
5. **Format your code**: Run `crystal tool format` to ensure consistent formatting
6. **Check code quality**: Run `ameba` if configured (see below)
7. **Commit your changes**: Use descriptive commit messages
8. **Push to your fork**: `git push origin feature/your-feature-name`
9. **Create a Pull Request**

## Development Setup

### Prerequisites

- Crystal >= 1.14.0
- Git
- For Linux backend testing: Docker, docker-compose, or Apple container (macOS 15.6+)

### Installation

```bash
git clone https://github.com/dsisnero/keyring.git
cd keyring
shards install
```

### Running Tests

```bash
# Run all tests
crystal spec
# or use the Makefile
make test

# Run specific test suites
crystal spec spec/keyring/file_backend_spec.cr
crystal spec spec/keyring/macos_backend_spec.cr
crystal spec spec/keyring/linux_backend_spec.cr

# Test Linux backend using containers
make test-linux
```

### Code Quality Tools

#### Crystal Formatter

Always format your code before submitting:

```bash
crystal tool format
```

#### Ameba (Static Code Analysis)

If ameba is configured as a development dependency:

```bash
shards install  # Ensure ameba is installed
ameba
```

## Code Style Guidelines

### General

- Follow Crystal's official style guide: https://crystal-lang.org/reference/conventions/coding_style.html
- Use 2-space indentation (as configured in `.editorconfig`)
- Use LF line endings
- Include trailing newline at end of files

### Naming Conventions

- Classes and modules: `PascalCase`
- Methods and variables: `snake_case`
- Constants: `SCREAMING_SNAKE_CASE`

### Documentation

- Document public APIs with Crystal's doc comments (`#` comments before methods/classes)
- Include type annotations for method parameters and return values
- Add comments for complex logic or non-obvious behavior

### Error Handling

- Use custom exception classes from `src/keyring/errors.cr`
- Provide meaningful error messages with context
- Log errors at appropriate levels (DEBUG, INFO, WARN, ERROR)

### Testing

- Write tests for new functionality
- Follow existing test patterns in the `spec/` directory
- Use descriptive test names that explain the expected behavior
- Clean up test data after tests run

## Project Structure

```
keyring/
├── src/keyring/           # Main source code
│   ├── backend.cr        # Abstract Backend interface
│   ├── windows_backend.cr
│   ├── macos_backend.cr
│   ├── linux_backend.cr
│   ├── file_backend.cr
│   ├── keyring.cr        # Main Keyring API
│   ├── credential.cr     # Credential model
│   ├── encryption.cr     # Password encryption
│   ├── config.cr         # Configuration system
│   ├── cli.cr           # Command-line interface
│   ├── errors.cr        # Exception classes
│   └── logging.cr       # Logging setup
├── spec/                 # Test suite
│   ├── keyring/         # Unit tests
│   ├── integration/     # Integration tests
│   └── support/         # Test helpers
├── docs/                # Documentation
└── examples/            # Usage examples
```

## Backend Development

### Platform-Specific Considerations

#### macOS Backend
- Uses Security.framework C API directly (not command-line tools)
- Performance is critical - avoid unnecessary API calls
- Handle permission dialogs gracefully
- See `docs/MACOS_IMPLEMENTATION.md` for details

#### Windows Backend
- Uses win32cr library for Windows Credential API
- Store metadata in credential comment field as JSON
- Handle Unicode strings properly with `to_utf16`

#### Linux Backend
- Uses libsecret FFI bindings
- Requires GNOME Keyring or KWallet
- Test using containers on non-Linux platforms
- See `docs/LINUX_BACKEND.md` for implementation details

#### File Backend
- Provides encrypted fallback storage
- Uses Sodium for encryption
- Implements atomic writes and file locking
- Supports XDG_DATA_HOME directory structure

### Adding a New Backend

1. Create a new class in `src/keyring/` that inherits from `Backend`
2. Implement all abstract methods from `Backend` class
3. Add `self.available?` method that returns `true` when the backend is available
4. Write comprehensive tests in `spec/keyring/`
5. Update backend selection logic in `src/keyring/keyring.cr` if needed
6. Document the backend in appropriate documentation files

## Commit Messages

Use descriptive commit messages that explain:

- **What** changed
- **Why** it changed (the problem being solved)
- **How** it changed (brief technical details)

Example:
```
Add timeout parameter to fetchUser()

- Added optional timeout parameter with default 5000ms
- Pass timeout to underlying fetch() call
- Updated tests to verify timeout behavior

Fixes issue with hanging requests on slow networks
```

## Pull Request Process

1. Ensure your PR addresses a single issue or feature
2. Update documentation if needed (README, CHANGELOG, etc.)
3. Add tests for new functionality
4. Ensure all CI checks pass
5. Request review from maintainers
6. Address review feedback
7. Once approved, a maintainer will merge your PR

## Release Process

Releases are managed by maintainers:

1. Update version in `shard.yml`
2. Update `CHANGELOG.md` with release notes
3. Create a git tag: `git tag vX.Y.Z`
4. Push tag: `git push origin vX.Y.Z`
5. GitHub Actions will create a release automatically (if configured)

## Getting Help

- Check existing documentation in `docs/` directory
- Review existing issues and pull requests
- Ask questions in issues (use the "question" label)

Thank you for contributing to Keyring!