# keyring

[![CI](https://github.com/dsisnero/keyring/actions/workflows/ci.yml/badge.svg)](https://github.com/dsisnero/keyring/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Crystal](https://img.shields.io/badge/crystal-%3E%3D1.14.0-blue.svg)](https://crystal-lang.org)

A Crystal implementation of the Python keyring library, providing secure password/secret storage across different platforms.

## Features

- Secure storage of passwords and credentials
- Multiple backend support:
  - **macOS Keychain** (via Security.framework C API) - 15/15 tests ✅
  - Windows Credential Manager (via win32cr)
  - **Linux Secret Service** (libsecret with GNOME Keyring/KWallet) - 25+ tests ✅
  - **File backend** (encrypted JSON storage with Sodium) - 28/28 tests ✅
- Password encryption support (Sodium SecretBox, Argon2)
- Command-line interface
- Configurable logging
- Import/export functionality
- High performance (direct C API calls)

## Installation

1. Add the dependency to your `shard.yml`:

```yaml
dependencies:
  keyring:
    github: dsisnero/keyring
```

2. Run `shards install`

## Usage

### As a Library

```crystal
require "keyring"

# Create a keyring instance
keyring = Keyring::Keyring.new

# Store a password
keyring.set_password("MyApp", "username", "secret123")

# Retrieve a password
password = keyring.get_password("MyApp", "username")

# Delete a password
keyring.delete_password("MyApp", "username")

# List all credentials (returns service/account pairs without passwords)
credentials = keyring.list_credentials
credentials.each do |cred|
  puts "Service: #{cred.service}, Account: #{cred.username}"
  # Fetch password separately if needed:
  # password = keyring.get_password(cred.service, cred.username)
end

# Search credentials
results = keyring.search("MyApp")
```

### Command Line Interface

```bash
# Get a password
keyring get -s MyApp -u username

# Set a password
keyring set -s MyApp -u username -p secret123

# Delete a password
keyring delete -s MyApp -u username

# List all credentials
keyring list

# Search credentials
keyring search -q "MyApp"

# Export credentials
keyring export -f credentials.json

# Import credentials
keyring import -f credentials.json
```

## Configuration

Configuration is stored in:
- Windows: `%APPDATA%\keyring\config.yml`
- Linux/macOS: `~/.config/keyring/config.yml`

Example configuration:
```yaml
preferred_backend: WindowsBackend
default_service: MyApp
encrypt_passwords: true
encryption_key: your-secret-key
log_level: INFO
log_file: ~/.keyring/keyring.log
```

## macOS Keychain Permissions

### First-Time Access

When your Crystal application first accesses the macOS Keychain, you may see a permission dialog. This is normal macOS security behavior.

### How Permissions Work

1. **Default Behavior**: By default, the application that creates a keychain item is trusted to access it without prompting.

2. **Permission Dialog**: If another application (or the same app rebuilt) tries to access the credential, macOS will show a dialog with three options:
   - **Deny**: Blocks this access attempt
   - **Allow**: Allows this one access
   - **Always Allow**: Adds the application to the trusted list

### For Development

When developing with Crystal, your compiled binaries change frequently. Each new compilation creates a "different" application from macOS's perspective. You have several options:

**Option 1: Use "Always Allow" (Recommended for Development)**
- Click "Always Allow" when prompted
- This trusts the specific binary path
- You'll need to do this again after recompiling if the binary changes

**Option 2: Build a Release Binary**
- Build your application once: `shards build --release`
- Use this same binary during development
- Only need to grant permission once per credential

**Option 3: Code Sign During Development**
- Sign your binary with an ad-hoc signature: `codesign -s - ./bin/myapp`
- Maintains consistent identity across rebuilds
- Free and simple for local development

### For Production/Distribution

If distributing your application:

1. **Code Signing**: Sign your application with a Developer ID
   ```bash
   codesign -s "Developer ID Application: Your Name" ./bin/myapp
   ```

2. **Notarization**: For macOS 10.15+, notarize your app with Apple

3. **Keychain Access Groups**: Consider using keychain access groups for shared access

### Checking Current Permissions

You can view and modify keychain item permissions using Keychain Access app:

1. Open **Keychain Access** (Applications > Utilities > Keychain Access)
2. Find your credential (search for service name)
3. Double-click the item
4. Go to the **Access Control** tab
5. View/modify which applications can access this item

### Troubleshooting

**Problem**: Permission dialogs appear every time I run my app

**Solution**:
- Build a release binary and use it consistently
- Or click "Always Allow" for each credential
- Or use the `-A` flag when creating credentials (development only)

**Problem**: "User interaction is not allowed" error

**Solution**:
- Make sure you're running the app in an interactive terminal
- Check that the keychain is unlocked
- Verify you have permission to access the keychain

## Development

### Local Development (macOS/Windows)

1. Clone the repository
2. Run `shards install`
3. Run tests with `crystal spec` or `make test`
4. Format code with `make format` or `crystal tool format`
5. Lint code with `make lint` or `ameba`
6. Run pre-commit checks with `make pre-commit` (format + lint)

### Linux Backend Development (Containers)

The Linux backend uses libsecret for GNOME Keyring/KWallet access. Use containers to test on macOS/Windows:

```bash
# Check which container runtime is available
make container-info

# Build container environment
make docker-build

# Run Linux backend tests
make test-linux

# Interactive development
make docker-dev
```

The Makefile automatically detects and uses the best available container runtime:
- **Apple container** (macOS 15.6+) - Fastest, native to macOS
- **docker-compose** - Standard fallback
- **docker** - Lightweight fallback

See [docs/LINUX_TESTING.md](docs/LINUX_TESTING.md) for container setup and [docs/LINUX_BACKEND.md](docs/LINUX_BACKEND.md) for implementation details.

## Continuous Integration

This project uses GitHub Actions for continuous integration and deployment:

### CI Pipeline
- **Tests**: Runs on Ubuntu, macOS, and Windows with Crystal 1.14.0 and latest
- **Linting**: Uses Ameba with custom configuration (.ameba.yml)
- **Formatting**: Crystal tool format check
- **Security**: Gitleaks scanning for secrets
- **Build**: Creates release binaries for all platforms when tags are pushed

### Release Process
When a new version tag (vX.Y.Z) is pushed:
1. CI runs all tests on all platforms
2. Binaries are built for each platform/architecture:
   - `keyring` (Linux x64)
   - `keyring` (macOS arm64)
   - `keyring.exe` (Windows x64)
3. All binaries are uploaded to the GitHub Release
4. Release notes are automatically generated

### Build Commands
- Local build: `shards build`
- Release build: `shards build --release`
- Test all: `make test` or `crystal spec`
- Format code: `make format` or `crystal tool format`
- Lint code: `make lint` or `ameba --fail-level Error`

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on how to contribute to this project.

### Quick Start

1. Fork the repository (<https://github.com/dsisnero/keyring/fork>)
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes and ensure tests pass (`make test`)
4. Format your code (`make format`) and check linting (`make lint`)
5. Commit your changes with descriptive messages
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

For more details, coding standards, and development setup, please read [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributors

- [Dominic Sisneros](https://github.com/dsisnero) - creator and maintainer

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
