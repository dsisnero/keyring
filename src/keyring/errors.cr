module Keyring
  class Error < Exception; end
  class NoBackendError < Error; end
  class PasswordSetError < Error; end
  class PasswordDeleteError < Error; end
  class BackendError < Error; end
  class KeyringError < Error; end
end
