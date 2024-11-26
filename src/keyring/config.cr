 require "yaml"
 require "file_utils"

 module Keyring
   class ConfigError < Error; end

   class Config
     include YAML::Serializable

     property preferred_backend : String?
     property default_service : String?
     property encrypt_passwords : Bool
     property encryption_key : String?
     property log_level : String
     property log_file : String?

     def self.default_config_path : String
       {% if flag?(:windows) %}
         File.join(ENV["APPDATA"]? || "", "keyring", "config.yml")
       {% else %}
         File.join(ENV["HOME"]? || "", ".config", "keyring", "config.yml")
       {% end %}
     end

     def initialize
       @preferred_backend = nil
       @default_service = nil
       @encrypt_passwords = true
       @encryption_key = nil
       @log_level = "INFO"
       @log_file = nil
     end

     def self.load : Config
       load(default_config_path)
     rescue
       new
     end

     def self.load(path : String) : Config
       return new unless File.exists?(path)

       config = Config.from_yaml(File.read(path))
       config.validate!
       config
     rescue ex : YAML::ParseException
       raise ConfigError.new("Invalid config file: #{ex.message}")
     end

     def save(path : String = Config.default_config_path)
       FileUtils.mkdir_p(File.dirname(path))
       File.write(path, to_yaml)
     end

     def validate!
       if @encrypt_passwords && !@encryption_key
         raise ConfigError.new("encryption_key must be set when encrypt_passwords is true")
       end
     end
   end
 end
