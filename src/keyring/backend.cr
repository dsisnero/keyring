module Keyring
  # Abstract base class for keyring backends
  abstract class Backend
    # Priority level for this backend (higher number = higher priority)
    property priority : Int32 = 1

    # Name of the backend
    abstract def name : String

    # Check if this backend is supported on the current system
    abstract def supported? : Bool

    # Check if this backend is available for use
    # (i.e., necessary dependencies are installed)
    abstract def available? : Bool

    # Get password stored for the username of the service
    abstract def get_password(service : String, username : String) : String?

    # Store the password for the username of the service
    abstract def set_password(service : String, username : String, password : String) : Bool

    # Delete the password for the username of the service
    abstract def delete_password(service : String, username : String) : Bool

    # Get a list of stored credentials
    abstract def get_credential(service : String, username : String?) : Credential?

    # Default implementation for credential handling
    def get_credentials(service : String) : Array(Credential)
      [] of Credential
    end

    # Verify that the backend is viable for use
    def viable? : Bool
      supported? && available?
    end
  end

  # Credential class to store username/password pairs
  class Credential
    getter service : String
    getter username : String
    getter password : String

    def initialize(@service : String, @username : String, @password : String)
    end

    def to_s : String
      "Credential(service='#{@service}', username='#{@username}')"
    end
  end

  # Backend loading error
  class BackendError < Exception
  end

  # Error when a password is not found
  class PasswordError < Exception
  end

  # Error when a backend is not available
  class InitError < Exception
  end
end
