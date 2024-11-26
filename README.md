# keyring

A Crystal implementation of the Python keyring library, providing secure password/secret storage across different platforms.

## Features

- Secure storage of passwords and credentials
- Multiple backend support:
  - Windows Credential Manager
  - Linux Secret Service (GNOME Keyring/KWallet)
- Password encryption support
- Command-line interface
- Configurable logging
- Import/export functionality

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

# List all credentials
credentials = keyring.list_credentials

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

## Development

1. Clone the repository
2. Run `shards install`
3. Run tests with `crystal spec`

## Contributing

1. Fork it (<https://github.com/dsisnero/keyring/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Dominic Sisneros](https://github.com/dsisnero) - creator and maintainer

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
