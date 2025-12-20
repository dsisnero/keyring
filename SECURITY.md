# Security Policy

## Supported Versions

Currently, only the latest version of Keyring is supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Keyring, please report it privately to the maintainer:

**Email**: dsisnero@gmail.com

### What to Include

When reporting a vulnerability, please include:

1. **Description**: A clear, detailed description of the vulnerability
2. **Impact**: Potential impact if exploited
3. **Steps to Reproduce**: Step-by-step instructions to reproduce the issue
4. **Proof of Concept**: If available, a proof-of-concept or exploit code
5. **Affected Versions**: Which versions of Keyring are affected
6. **Mitigation Suggestions**: Any suggestions for fixing or mitigating the issue

### Response Process

1. **Acknowledgement**: You will receive an acknowledgement within 48 hours
2. **Investigation**: The maintainer will investigate the report
3. **Update**: You'll receive regular updates on the investigation progress
4. **Fix Development**: A fix will be developed and tested
5. **Release**: A security release will be published with the fix
6. **Disclosure**: Public disclosure after the fix is available

## Security Considerations

### Password Storage

Keyring stores passwords using platform-native secure storage:

- **macOS**: Keychain Services (Security.framework)
- **Windows**: Credential Manager (Windows Credential API)
- **Linux**: Secret Service (libsecret with GNOME Keyring/KWallet)
- **File Backend**: Encrypted JSON files using Sodium (SecretBox with Argon2)

### Encryption

When using the file backend or when encryption is enabled:

- Passwords are encrypted using Sodium's `crypto_secretbox_easy`
- Keys are derived using Argon2 (memory-hard password hashing)
- Encryption keys should be kept secure and not committed to version control

### Memory Safety

- Crystal provides memory safety through its type system
- Sensitive data (passwords) are cleared from memory when possible
- Backends use platform APIs designed for secure credential storage

### Platform-Specific Security

#### macOS Keychain
- Items are stored in the user's keychain with appropriate access controls
- Applications must be authorized to access keychain items
- Consider code signing for production applications

#### Windows Credential Manager
- Credentials are stored encrypted by Windows
- Access requires appropriate user permissions
- Credentials can be scoped to user or machine

#### Linux Secret Service
- Uses D-Bus for communication with secret service daemon
- Requires unlocked keyring (GNOME Keyring or KWallet)
- Supports session-based or permanent storage

### Best Practices for Users

1. **Use Platform Backends**: Prefer native platform backends over file backend when available
2. **Secure Configuration**: Keep configuration files with encryption keys secure
3. **Regular Updates**: Keep Keyring and its dependencies updated
4. **Audit Logs**: Monitor logs for suspicious activity
5. **Least Privilege**: Run applications with minimal necessary permissions

### Best Practices for Developers

1. **Input Validation**: Validate all inputs to prevent injection attacks
2. **Error Handling**: Handle errors gracefully without leaking sensitive information
3. **Secure Defaults**: Use secure defaults for configuration
4. **Dependency Management**: Keep dependencies updated and audit for vulnerabilities
5. **Code Review**: Conduct security-focused code reviews

## Dependency Security

Keyring uses the following security-critical dependencies:

- **Sodium**: For encryption in file backend (via sodium.cr)
- **win32cr**: For Windows Credential Manager access
- **libsecret**: For Linux Secret Service access (via FFI)

All dependencies are regularly reviewed for security updates.

## Security Audit

Periodic security audits are conducted to identify and address vulnerabilities. If you're interested in conducting a security audit or review, please contact the maintainer.

## Credits

Security researchers who responsibly disclose vulnerabilities will be credited in security advisories and release notes (unless they prefer to remain anonymous).