require "yaml"
require "file_utils"
require "base64"
require "./platform"

module Keyring
  class Config
    include YAML::Serializable

    property preferred_backend : String?
    property backend_priority : Array(String)?
    property default_service : String?
    property? encrypt_passwords : Bool
    property encryption_key : String?
    property encryption_type : String?
    property encryption_public_key : String?
    property encryption_secret_key : String?
    property log_level : String
    property log_file : String?

    def self.default_config_path : String
      File.join(Platform.config_root, "config.yml")
    end

    def initialize
      @preferred_backend = nil
      @backend_priority = nil
      @default_service = nil
      @encrypt_passwords = false
      @encryption_key = nil
      @encryption_type = nil
      @encryption_public_key = nil
      @encryption_secret_key = nil
      @log_level = "INFO"
      @log_file = nil
    end

    def self.load : Config
      load(default_config_path)
    rescue
      new
    end

    def self.load(path : String) : Config
      config = if File.exists?(path)
                 Config.from_yaml(File.read(path))
               else
                 new
               end

      # Apply environment variable overrides
      config.apply_env_overrides
      config.validate!
      config
    rescue ex : YAML::ParseException
      raise ConfigError.new("Invalid config file: #{ex.message}")
    end

    # Apply environment variable overrides
    def apply_env_overrides
      if backend = ENV["KEYRING_BACKEND"]?
        @preferred_backend = backend
      end

      if priority = ENV["KEYRING_BACKEND_PRIORITY"]?
        # Comma-separated list, e.g., "MacOsKeyChainBackend,LinuxSecretServiceBackend,FileBackend"
        @backend_priority = priority.split(',').map(&.strip).reject(&.empty?)
      end

      if log_level = ENV["KEYRING_LOG_LEVEL"]?
        @log_level = log_level
      end

      if key = ENV["KEYRING_ENCRYPTION_KEY"]?
        @encryption_key = key
      end

      return unless encrypt = ENV["KEYRING_ENCRYPT"]?
      @encrypt_passwords = encrypt.downcase == "true"
    end

    def set_property(key : String, value : String)
      case key.downcase
      when "preferred_backend"
        @preferred_backend = value
      when "backend_priority"
        @backend_priority = value.split(',').map(&.strip).reject(&.empty?)
      when "default_service"
        @default_service = value
      when "encrypt_passwords"
        @encrypt_passwords = value.downcase.in?("true", "1", "yes")
      when "encryption_key"
        @encryption_key = value
      when "log_level"
        @log_level = value
      when "encryption_type"
        @encryption_type = value
      when "encryption_public_key"
        @encryption_public_key = value
      when "encryption_secret_key"
        @encryption_secret_key = value
      when "log_file"
        @log_file = value
      else
        raise ConfigError.new("Unknown config key: #{key}")
      end
    end

    def save(path : String = Config.default_config_path)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, to_yaml)
    end

    def validate!
      if @encrypt_passwords && !@encryption_key
        raise ConfigError.new("encryption_key must be set when encrypt_passwords is true")
      end

      raise ConfigError.new("Invalid log level") unless valid_log_level?(@log_level)

      validate_encryption_config
    end

    private def valid_log_level?(level : String) : Bool
      ["DEBUG", "INFO", "WARN", "ERROR", "FATAL"].includes?(level.upcase)
    end

    private def validate_encryption_config
      # Validate encryption key format
      if key = @encryption_key
        begin
          Base64.decode(key)
        rescue
          raise ConfigError.new("Invalid encryption_key format - must be valid base64")
        end
      end
      nil
    end
  end
end
