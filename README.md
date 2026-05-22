# keyring

[![CI](https://github.com/dsisnero/keyring/actions/workflows/ci.yml/badge.svg)](https://github.com/dsisnero/keyring/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Crystal](https://img.shields.io/badge/crystal-%3E%3D1.15.0-blue.svg)](https://crystal-lang.org)

A Crystal port of [jaraco/keyring](https://github.com/jaraco/keyring) (Python keyring v25.7.0), providing cross-platform secure password and secret storage.

## Features

- **Cross-platform** — macOS Keychain, Windows Credential Manager, Linux Secret Service/KWallet, and an encrypted file fallback
- **Automatic backend selection** — picks the best available backend by platform priority
- **Runtime failover** — circuit breakers + automatic backend switching on persistent failure
- **Password encryption** — Sodium SecretBox (XSalsa20-Poly1305) and Argon2 hashing
- **Metadata storage** — attach arbitrary key/value pairs to credentials (macOS Keychain, Windows Credential Manager)
- **Backend registry** — auto-registration via `Backend.register(self)`; discover all available backends at runtime
- **Retry with backoff** — configurable retry policy for transient failures
- **Operation metrics** — per-backend per-operation latency and success/failure tracking
- **CLI** — full command-line interface with get/set/delete/list/search/export/import

## Backends

| Backend | Platforms | Priority | Status |
|---------|-----------|----------|--------|
| `MacOsKeyChainBackend` | macOS | 5 | Native Security.framework C API |
| `WindowsBackend` | Windows | 5 | Credential Manager via win32cr |
| `LinuxSecretServiceBackend` | Linux | 5 | libsecret + D-Bus Secret Service |
| `KWalletBackend` | Linux (KDE) | 4.9 | KDE KWallet5 via D-Bus |
| `KWallet4Backend` | Linux (KDE4) | 4.8 | KDE KWallet4 via D-Bus |
| `FileBackend` | All | 4 | Encrypted JSON file (Sodium) |
| `ChainerBackend` | All | — | Iterates all viable backends |
| `NullBackend` | All | -1 | No-op (use `--disable`) |
| `FailBackend` | All | 0 | Always raises (fallback) |

## Installation

1. Add to `shard.yml`:

```yaml
dependencies:
  keyring:
    github: dsisnero/keyring
```

2. Run `shards install`

3. Install system dependencies:

| OS | Command |
|----|---------|
| macOS | `brew install libsodium` |
| Ubuntu | `sudo apt install libsodium-dev libsecret-1-dev` |
| Windows | `vcpkg install` (uses vcpkg.json) |

## Usage

### Module-Level API

```crystal
require "keyring"

# Store a password
Keyring.set_password("myapp", "alice", "s3cret")

# Retrieve a password
password = Keyring.get_password("myapp", "alice")
puts password # => "s3cret"

# Get a credential (username + password)
cred = Keyring.get_credential("myapp", "alice")
puts cred.username # => "alice"
puts cred.password # => "s3cret"

# Delete a password
Keyring.delete_password("myapp", "alice")

# Get password (returns nil if not found)
Keyring.get_password("myapp", "nobody") # => nil
```

### Instance API (Multiple Keyrings)

```crystal
keyring = Keyring::Keyring.new

keyring.set_password("myapp", "alice", "s3cret")
keyring.get_password("myapp", "alice")

# List all credentials
keyring.list_credentials.each do |cred|
  puts "#{cred.service}:#{cred.username}"
end

# Search
keyring.search("alice")

# List services
keyring.list_services # => ["myapp"]

# List usernames for a service
keyring.list_usernames("myapp") # => ["alice"]

# Export/import
keyring.export_credentials("/tmp/creds.json")
keyring.import_credentials("/tmp/creds.json")
```

### Backend Selection

```crystal
# Use a specific backend by name
keyring = Keyring::Keyring.new
keyring.switch_to_backend("FileBackend")

# Or set globally
Keyring.set_keyring(Keyring::FileBackend.new)

# Discover all available backends
Keyring.get_all_keyring.each do |backend|
  puts backend.class.display_name
end
```

## Command Line Interface

```bash
# Basic operations
keyring get -s myapp -u alice          # get password (plain text)
keyring get -s myapp -u alice --mode creds  # get username + password
keyring set -s myapp -u alice          # set password (interactive prompt)
keyring delete -s myapp -u alice       # delete password

# List, search, export
keyring list                           # list all credentials
keyring list --output json             # JSON output
keyring search -q "alice"              # search by query
keyring export -f creds.json           # export all credentials
keyring import -f creds.json           # import from file

# Management
keyring backend list                    # list available backends (* = active)
keyring backend switch FileBackend      # switch backend at runtime
keyring config show                     # show current configuration
keyring config set -k encrypt_passwords -v true  # update config
keyring diagnose                        # show config/data paths
keyring generate-key                    # generate encryption key
keyring update -s myapp -u alice        # update existing password
keyring --disable                       # disable keyring (use NullBackend, requires no existing config)

# Shell completion
keyring completion bash                # generate bash completions
keyring completion zsh                 # generate zsh completions
```

### Pipe Input

```bash
echo "mypassword" | keyring set -s myapp -u alice
```

## Configuration

Configuration file: `~/.config/keyring_cr/config.yml` (Linux/macOS) or `%APPDATA%\keyring_cr\config.yml` (Windows).

```yaml
# Preferred backend (auto-detected if not set)
preferred_backend: MacOsKeyChainBackend

# Backend selection priority order
backend_priority:
  - MacOsKeyChainBackend
  - FileBackend

# Password encryption
encrypt_passwords: true
encryption_key: your-sodium-secret-key

# Logging
log_level: DEBUG
log_file: ~/.keyring_cr/keyring.log

# Default service name
default_service: myapp
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `KEYRING_BACKEND` | Force a specific backend by name |
| `KEYRING_PROPERTY_<name>` | Set arbitrary backend properties |
| `KEYRING_ENCRYPT` | Override encrypt_passwords (true/false) |
| `KEYRING_LOG_LEVEL` | Override logging level |

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

## Architecture

```
Keyring::Backend (abstract)
  ├── MacOsKeyChainBackend     — macOS Keychain via Security.framework
  ├── WindowsBackend           — Windows Credential Manager via win32cr
  ├── LinuxSecretServiceBackend — Linux Secret Service via libsecret
  ├── KWalletBackend           — KDE KWallet5 via D-Bus
  ├── KWallet4Backend          — KDE KWallet4 via D-Bus
  ├── ChainerBackend           — Iterates all viable backends
  ├── FileBackend              — Encrypted JSON file (universal fallback)
  ├── NullBackend              — No-op (disable keyring)
  └── FailBackend              — Always raises (last-resort fallback)
```

See [docs/architecture.md](docs/architecture.md) for details.

## Development

```bash
shards install          # Install dependencies
crystal spec            # Run all 313 tests
make format-check       # Check code formatting
make lint               # Run Ameba linter
shards build            # Build CLI binary
```

### Linux Backend Testing (Container)

```bash
make docker-build       # Build container
make test-linux         # Run Linux-specific tests in container
```

## Continuous Integration

GitHub Actions runs on every push/PR to main:
- **Test** — macOS, Windows, Ubuntu (tests + binary build)
- **Lint** — Crystal format check + Ameba
- **KWallet** — KDE KWallet backend tests with D-Bus
- **Binaries** — Release binaries for all platforms (on main push)
- **Release** — GitHub Release with platform binaries (on tag push)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Make changes, add tests
4. Run quality gates: `crystal spec && make lint && make format-check`
5. Commit with conventional commit messages (`feat:`, `fix:`, `test:`, `docs:`, `chore:`)
6. Push and open a Pull Request

See [docs/development.md](docs/development.md) for detailed setup and conventions.

## License

MIT — see [LICENSE](LICENSE) for details.

## Credits

- [jaraco/keyring](https://github.com/jaraco/keyring) — upstream Python library (v25.7.0)
- [Dominic Sisneros](https://github.com/dsisnero) — Crystal port
