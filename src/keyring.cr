require "./keyring/backend"
require "./keyring/chainer_backend"
require "./keyring/config"
require "./keyring/credential"
require "./keyring/encryption"
require "./keyring/errors"
require "./keyring/fail_backend"
require "./keyring/file_backend"
require "./keyring/logging"
require "./keyring/null_backend"
require "./keyring/platform"
require "./keyring/keyring"

{% if flag?(:linux) %}
  require "./keyring/linux_backend"
{% end %}

{% if flag?(:darwin) %}
  require "./keyring/macos_backend"
{% end %}

{% if flag?(:windows) %}
  require "./keyring/windows_backend"
{% end %}
