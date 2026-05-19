require "spec"
require "../src/keyring"
require "./support/mock_backend"
require "./support/test_helpers"

Spec.before_each do
  Keyring::Keyring.reset_backend_overrides
  Keyring::Keyring.reset_circuit_breakers
  Keyring::Metrics.reset
end
