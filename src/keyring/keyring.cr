 require "./backend"
 require "./config"
 require "./encryption"
 require "./errors"
 require "./logging"
 require "./windows_backend"

 module Keyring
   VERSION = "0.1.0"

   class Keyring
     getter backend : Backend
     getter config : Config

     def initialize(config_path : String? = nil)
       @config = config_path ? Config.load(config_path) : Config.load
       setup_logging
       @backend = get_preferred_backend
       Log.info { "Initialized keyring with backend: #{@backend.class}" }
     end

     def get_password(service : String, username : String) : String?
       Log.debug { "Getting password for #{service}:#{username}" }
       if cred = get_credential(service, username)
         return @config.encrypt_passwords ? cred.decrypt_password : cred.password
       end
     end

     def set_password(service : String, username : String, password : String)
       Log.debug { "Setting password for #{service}:#{username}" }
       cred = Credential.new(
         service: service,
         username: username,
         password: password,
         encryption_key: @config.encryption_key
       )
       @backend.set_password(service, username, cred.password.not_nil!)
     end

     def delete_password(service : String, username : String)
       Log.debug { "Deleting password for #{service}:#{username}" }
       @backend.delete_password(service, username)
     end

     def get_credential(service : String, username : String) : Credential?
       @backend.get_credential(service, username)
     end

     def list_credentials : Array(Credential)
       @backend.list_credentials
     end

     def list_services : Array(String)
       list_credentials.map(&.service).uniq
     end

     def list_usernames(service : String) : Array(String)
       list_credentials.select { |c| c.service == service }.map(&.username)
     end

     def search(query : String) : Array(Credential)
       list_credentials.select do |cred|
         cred.service.includes?(query) ||
         cred.username.includes?(query) ||
         cred.metadata.values.any? { |v| v.includes?(query) }
       end
     end

     def export_credentials(path : String)
       Log.info { "Exporting credentials to #{path}" }
       File.write(path, list_credentials.to_json)
     end

     def import_credentials(path : String)
       Log.info { "Importing credentials from #{path}" }
       credentials = Array(Credential).from_json(File.read(path))
       credentials.each do |cred|
         set_password(cred.service, cred.username, cred.password.not_nil!)
         cred.metadata.each do |k, v|
           set_metadata(cred.service, cred.username, k, v)
         end
       end
     end

     private def get_preferred_backend : Backend
       backends = [
         WindowsBackend,
         # Add more backends here as they're implemented
       ]

       if preferred = @config.preferred_backend
         backend_class = backends.find { |b| b.name.ends_with?(preferred) }
         if backend_class && backend_class.available?
           return backend_class.new
         end
         Log.warn { "Preferred backend #{preferred} not available" }
       end

       backends.each do |backend_class|
         if backend_class.available?
           return backend_class.new
         end
       end

       raise NoBackendError.new("No suitable keyring backend found")
     end

     private def setup_logging
       Keyring.setup_logging(@config)
     end
   end
 end
