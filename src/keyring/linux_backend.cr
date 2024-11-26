 require "./backend"
 require "./errors"

 {% if flag?(:linux) %}
   @[Link("secret-1")]
   lib LibSecret
     fun secret_password_store_sync(schema : Void*, cancellable : Void*, error : Void**,
                                  attribute_name : LibC::Char*, attribute_value : LibC::Char*,
                                  password : LibC::Char*, ...) : LibC::Int

     fun secret_password_lookup_sync(schema : Void*, cancellable : Void*, error : Void**,
                                   attribute_name : LibC::Char*, attribute_value : LibC::Char*,
                                   ...) : LibC::Char*

     fun secret_password_clear_sync(schema : Void*, cancellable : Void*, error : Void**,
                                  attribute_name : LibC::Char*, attribute_value : LibC::Char*,
                                  ...) : LibC::Int

     fun secret_password_free(password : LibC::Char*)
   end
 {% end %}

 module Keyring
   class LinuxSecretServiceBackend < Backend
     SCHEMA_ATTRIBUTE = "keyring-crystal"

     def self.available? : Bool
       {% if flag?(:linux) %}
         true
       {% else %}
         false
       {% end %}
     end

     def get_password(service : String, username : String) : String?
       {% if flag?(:linux) %}
         target = "#{service}:#{username}"
         password = LibSecret.secret_password_lookup_sync(nil, nil, nil,
                                                        SCHEMA_ATTRIBUTE, target, Pointer(Void).null)
         if password
           begin
             return String.new(password)
           ensure
             LibSecret.secret_password_free(password)
           end
         end
       {% end %}
       nil
     end

     def set_password(service : String, username : String, password : String)
       {% if flag?(:linux) %}
         target = "#{service}:#{username}"
         result = LibSecret.secret_password_store_sync(nil, nil, nil,
                                                     SCHEMA_ATTRIBUTE, target,
                                                     password, Pointer(Void).null)
         if result == 0
           raise PasswordSetError.new("Failed to store password in secret service")
         end
       {% else %}
         raise NoBackendError.new("Linux Secret Service backend not available")
       {% end %}
     end

     def delete_password(service : String, username : String)
       {% if flag?(:linux) %}
         target = "#{service}:#{username}"
         result = LibSecret.secret_password_clear_sync(nil, nil, nil,
                                                     SCHEMA_ATTRIBUTE, target,
                                                     Pointer(Void).null)
         if result == 0
           raise PasswordDeleteError.new("Failed to delete password from secret service")
         end
       {% else %}
         raise NoBackendError.new("Linux Secret Service backend not available")
       {% end %}
     end

     def get_credential(service : String, username : String) : Credential?
       if password = get_password(service, username)
         Credential.new(service, username, password)
       end
     end

     def list_credentials : Array(Credential)
       # TODO: Implement listing all credentials
       # This requires additional libsecret functions for searching/listing items
       [] of Credential
     end
   end
 end
