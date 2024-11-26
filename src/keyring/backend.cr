module Keyring
  abstract class Backend
    abstract def self.available? : Bool
    abstract def get_password(service : String, username : String) : String?
    abstract def set_password(service : String, username : String, password : String)
    abstract def delete_password(service : String, username : String)
    abstract def get_credential(service : String, username : String) : Credential?
    abstract def list_credentials : Array(Credential)
  end
end
