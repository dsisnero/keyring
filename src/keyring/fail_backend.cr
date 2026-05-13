require "./backend"
require "./errors"

module Keyring
  # Fail backend that raises errors on every operation.
  # Used as a fallback when no suitable backend is available.
  # Priority: 0.
  #
  # Ported from: python-keyring keyring/backends/fail.py (v25.7.0)
  class FailBackend < Backend
    getter error_message : String

    def self.available? : Bool
      true
    end

    def initialize
      @error_message = "No recommended backend was available. " \
                       "Install a recommended 3rd party backend package; " \
                       "or, install the keyrings.alt package if you want " \
                       "to use the non-recommended backends. " \
                       "See https://pypi.org/project/keyring for details."
    end

    def initialize(@error_message : String)
    end

    def get_password(service : String, username : String) : String?
      raise NoBackendError.new(@error_message)
    end

    def set_password(service : String, username : String, password : String)
      raise NoBackendError.new(@error_message)
    end

    def delete_password(service : String, username : String)
      raise NoBackendError.new(@error_message)
    end

    def get_credential(service : String, username : String) : Credential?
      raise NoBackendError.new(@error_message)
    end

    def list_credentials : Array(Credential)
      raise NoBackendError.new(@error_message)
    end
  end
end
