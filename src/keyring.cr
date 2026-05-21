require "./keyring/backend"
require "./keyring/config"
require "./keyring/credential"
require "./keyring/encryption"
require "./keyring/errors"
require "./keyring/logging"
require "./keyring/metrics"
require "./keyring/platform"
require "./keyring/retryable"
require "./keyring/circuit_breaker"

# Platform-specific backends register first (higher priority)
{% if flag?(:linux) %}
  require "./keyring/kwallet_backend"
  require "./keyring/linux_backend"
{% end %}

{% if flag?(:darwin) %}
  require "./keyring/macos_backend"
{% end %}

{% if flag?(:windows) %}
  require "./keyring/windows_backend"
{% end %}

# Generic backends register after platform backends (fallback)
require "./keyring/file_backend"
require "./keyring/chainer_backend"
require "./keyring/null_backend"
require "./keyring/fail_backend"

require "./keyring/keyring"
