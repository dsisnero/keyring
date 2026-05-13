require "./backend"
require "./errors"

module Keyring
  # Null/degenerate backend that returns nil for every operation.
  # Used for disabling keyring functionality.
  # Priority is -1 (lower than any real backend).
  #
  # Ported from: python-keyring keyring/backends/null.py (v25.7.0)
  class NullBackend < Backend
    def self.available? : Bool
      true
    end

    def get_password(service : String, username : String) : String?
      nil
    end

    def set_password(service : String, username : String, password : String)
      # no-op
    end

    def delete_password(service : String, username : String)
      # no-op
    end

    def get_credential(service : String, username : String) : Credential?
      nil
    end

    def list_credentials : Array(Credential)
      [] of Credential
    end
  end
end
