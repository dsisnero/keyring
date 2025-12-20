require "yaml"
require "file_utils"
require "base64"

module Keyring
  class Config
    include YAML::Serializable

    property preferred_backend : String?
    property backend_priority : Array(String)?
    property default_service : String?
    property encrypt_passwords : Bool
    property encryption_key : String?
    property log_level : String
    property log_file : String?

    def self.default_config_path : String
      base_dir = ENV["XDG_CONFIG_HOME"]? || default_config_dir
      File.join(base_dir, "keyring", "config.yml")
    end

    def self.default_config_dir : String
      {% if flag?(:windows) %}
        File.join(ENV["APPDATA"]? || "", "keyring", "config.yml")
      {% else %}
        File.join(ENV["HOME"]? || "", ".config", "keyring", "config.yml")
      {% end %}
    end

    def initialize
      @preferred_backend = nil
      @backend_priority = nil
      @default_service = nil
      @encrypt_passwords = false # Default to false to avoid validation error
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
