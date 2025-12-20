---
name: Bug Report
about: Report a bug or unexpected behavior in Keyring
title: '[BUG] '
labels: ['bug', 'needs-triage']
assignees: ''
---

## Bug Description
A clear and concise description of what the bug is.

## Steps to Reproduce
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Actual behavior**
A clear and concise description of what actually happened.

## Environment
- **OS**: [e.g. macOS 15.6, Ubuntu 22.04, Windows 11]
- **Crystal Version**: [e.g. 1.14.0]
- **Keyring Version**: [e.g. 0.1.0]
- **Backend**: [e.g. macOS Keychain, Windows Credential Manager, Linux Secret Service, File Backend]

## Configuration
If applicable, share relevant parts of your configuration:
```yaml
# ~/.config/keyring/config.yml or %APPDATA%\keyring\config.yml
```

## Logs
If applicable, add logs or error messages:
```bash
# Run with debug logging enabled
KEYRING_LOG_LEVEL=DEBUG keyring [command]
```

## Additional Context
Add any other context about the problem here.

- [ ] I have searched existing issues and this is not a duplicate
- [ ] I have included all relevant environment information
- [ ] I have provided steps to reproduce the issue
- [ ] I have included relevant logs or error messages