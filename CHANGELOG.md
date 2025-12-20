# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial open source project infrastructure setup
- GitHub Actions CI workflow for cross-platform testing
- Pre-commit hooks for code formatting and linting
- Ameba configuration for code quality
- CONTRIBUTING.md guidelines
- SECURITY.md policy
- Issue and pull request templates

## [0.1.0] - 2025-12-19

### Added
- Complete cross-platform backend implementations:
  - macOS Keychain backend using Security.framework C API (15/15 tests passing, 6-8x faster than command-line approach)
  - Windows Credential Manager backend with full credential enumeration
  - Linux Secret Service backend with libsecret FFI bindings (25+ comprehensive tests)
  - File backend with encrypted JSON storage (28/28 tests passing)
- Core API with full CRUD operations (get, set, delete, update, list)
- Password encryption using Sodium (SecretBox with Argon2 key derivation)
- Configuration system with environment variable overrides
- Command-line interface with all basic operations (get, set, delete, list, search, export, import)
- Comprehensive test suite (118 examples, 0 failures, 0 errors, 22 pending)
- Docker/container testing environment for Linux backend (supports Apple container, docker-compose, docker)
- Backend priority system with automatic fallback
- Metadata support for all backends (Windows, macOS, Linux, File)
- Logging system with configurable levels
- Error handling with custom exception types

### Technical Highlights
- **Performance**: macOS backend 6-8x faster than command-line approach, list_credentials with 176+ items in 20ms
- **Security**: Encrypted file storage, proper memory management, secure password handling
- **Reliability**: Atomic writes, file locking, backup/restore on failure, concurrent access support
- **Cross-platform**: Native APIs on all major platforms (Security.framework, Windows Credential API, libsecret)
- **Testing**: 146 total test examples, comprehensive backend contract tests

### Documentation
- README.md with usage examples and platform-specific guidance
- AGENTS.md for AI coding assistant guidance
- plan.md with comprehensive implementation roadmap
- LINUX_BACKEND.md and LINUX_TESTING.md for Linux-specific documentation
- MACOS_IMPLEMENTATION.md for macOS backend details

[Unreleased]: https://github.com/dsisnero/keyring/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dsisnero/keyring/releases/tag/v0.1.0