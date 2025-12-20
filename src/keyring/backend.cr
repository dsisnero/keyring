require "./credential"

module Keyring
  abstract class Backend
    # abstract def self.available? : Bool
    abstract def get_password(service : String, username : String) : String?
    abstract def set_password(service : String, username : String, password : String)
    abstract def delete_password(service : String, username : String)
    abstract def get_credential(service : String, username : String) : Credential?
    abstract def list_credentials : Array(Credential)

    # Optional capabilities
    def supports_metadata? : Bool
      false
    end

    # Optional: store a metadata key/value for an existing credential
    # Default: not supported
    def set_metadata(service : String, username : String, key : String, value : String)
      raise KeyringError.new("Metadata not supported by this backend")
    end
  end
end
