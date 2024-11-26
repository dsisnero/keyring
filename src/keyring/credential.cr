 require "json"
 require "time"

 module Keyring
   class Credential
     include JSON::Serializable

     property service : String
     property username : String
     property password : String?
     property created_at : Time
     property modified_at : Time
     property metadata : Hash(String, String)
     property encrypted : Bool

     @[JSON::Field(ignore: true)]
     getter encryption_key : String?

     def initialize(@service, @username, @password = nil, @encryption_key = nil)
       @created_at = Time.utc
       @modified_at = @created_at
       @metadata = {} of String => String
       @encrypted = false
       encrypt_if_needed
     end

     def password=(new_password : String?)
       @password = new_password
       @modified_at = Time.utc
       encrypt_if_needed
     end

     def add_metadata(key : String, value : String)
       @metadata[key] = value
       @modified_at = Time.utc
     end

     def remove_metadata(key : String)
       @metadata.delete(key)
       @modified_at = Time.utc
     end

     private def encrypt_if_needed
       return if !@password || @encrypted || !@encryption_key
       @password = Encryption.encrypt(@password.not_nil!, @encryption_key.not_nil!)
       @encrypted = true
     end

     def decrypt_password : String?
       return @password if !@encrypted || !@password || !@encryption_key
       Encryption.decrypt(@password.not_nil!, @encryption_key.not_nil!)
     end

     def to_s(io : IO)
       io << "Credential(service: #{@service}, username: #{@username}, " \
             "created: #{@created_at}, modified: #{@modified_at})"
     end
   end
 end
