require "./backend"
require "./credential"
require "./encryption"
require "./errors"
require "json"
require "file_utils"

module Keyring
  # File-based backend that stores credentials in an encrypted JSON file
  # This serves as a fallback when platform-specific backends are unavailable
  class FileBackend < Backend
    DEFAULT_FILENAME = "credentials.enc.json"

    getter storage_path : String
    property encryption_key : String

    @credentials : Hash(String, Credential)
    @file_lock : File?

    def self.available? : Bool
      true # File backend is always available
    end

    def self.default_storage_path : String
      # Use XDG_DATA_HOME if set, otherwise use platform-specific default
      base_dir = ENV["XDG_DATA_HOME"]? || default_data_dir
      File.join(base_dir, "keyring", DEFAULT_FILENAME)
    end

    private def self.default_data_dir : String
      {% if flag?(:windows) %}
        ENV["LOCALAPPDATA"]? || File.join(ENV["USERPROFILE"]? || "", "AppData", "Local")
      {% else %}
        File.join(ENV["HOME"]? || "", ".local", "share")
      {% end %}
    end

    def initialize(storage_path : String? = nil, encryption_key : String? = nil)
      @storage_path = storage_path || FileBackend.default_storage_path
      @encryption_key = encryption_key || auto_generate_key(@storage_path)
      @credentials = {} of String => Credential
      @file_lock = nil

      ensure_storage_directory
      load_credentials
    end

    def get_password(service : String, username : String) : String?
      key = make_key(service, username)
      @credentials[key]?.try(&.password)
    end

    def set_password(service : String, username : String, password : String)
      key = make_key(service, username)

      # Create or update credential
      if existing = @credentials[key]?
        existing.password = password
      else
        @credentials[key] = Credential.new(service, username, password)
      end

      save_credentials
    end

    def delete_password(service : String, username : String)
      key = make_key(service, username)

      unless @credentials.has_key?(key)
        raise PasswordDeleteError.new("Password not found: #{service}:#{username}")
      end

      @credentials.delete(key)
      save_credentials
    end

    def get_credential(service : String, username : String) : Credential?
      key = make_key(service, username)
      @credentials[key]?
    end

    def list_credentials : Array(Credential)
      @credentials.values
    end

    private def make_key(service : String, username : String) : String
      "#{service}:#{username}"
    end

    private def ensure_storage_directory
      dir = File.dirname(@storage_path)
      created = false

      unless Dir.exists?(dir)
        Dir.mkdir_p(dir)
        created = true
      end

      # Set directory permissions to 0700 (user only) if we created it
      {% unless flag?(:windows) %}
        if created
          begin
            File.chmod(dir, 0o700)
          rescue File::Error
            # Ignore permission errors (e.g., for system directories like /tmp)
          end
        end
      {% end %}
    end

    private def auto_generate_key(storage_path : String) : String
      key_path = File.join(File.dirname(storage_path), ".keyring_key")

      if File.exists?(key_path)
        # Load existing key
        File.read(key_path).strip
      else
        # Generate new key
        key = Encryption.generate_key

        # Save key with restricted permissions
        File.write(key_path, key)
        {% unless flag?(:windows) %}
          File.chmod(key_path, 0o600)
        {% end %}

        key
      end
    end

    private def load_credentials
      return unless File.exists?(@storage_path)

      with_file_lock do
        begin
          # Read encrypted file
          encrypted_content = File.read(@storage_path)

          # Decrypt content
          json_content = Encryption.decrypt(encrypted_content, @encryption_key)

          # Parse JSON
          credentials_data = Array(Credential).from_json(json_content)

          # Store in hash
          @credentials.clear
          credentials_data.each do |cred|
            key = make_key(cred.service, cred.username)
            @credentials[key] = cred
          end
        rescue ex : JSON::ParseException
          Log.error { "Failed to parse credentials file: #{ex.message}" }
          raise BackendError.new("Corrupted credentials file")
        rescue ex : EncryptionError
          Log.error { "Failed to decrypt credentials file: #{ex.message}" }
          raise BackendError.new("Failed to decrypt credentials file - wrong key?")
        end
      end
    end

    private def save_credentials
      with_file_lock do
        # Create backup if file exists
        create_backup if File.exists?(@storage_path)

        begin
          # Serialize to JSON
          json_content = @credentials.values.to_json

          # Encrypt content
          encrypted_content = Encryption.encrypt(json_content, @encryption_key)

          # Write atomically using temp file
          temp_path = "#{@storage_path}.tmp"
          File.write(temp_path, encrypted_content)

          # Set permissions before moving
          {% unless flag?(:windows) %}
            File.chmod(temp_path, 0o600)
          {% end %}

          # Atomic rename
          File.rename(temp_path, @storage_path)

          # Clean up old backups
          cleanup_old_backups
        rescue ex
          # Restore from backup if save failed
          restore_from_backup if File.exists?("#{@storage_path}.backup")
          raise BackendError.new("Failed to save credentials: #{ex.message}")
        end
      end
    end

    private def with_file_lock(&)
      lock_path = "#{@storage_path}.lock"

      # Create lock directory if it doesn't exist
      Dir.mkdir_p(File.dirname(lock_path))

      # Open lock file (create if doesn't exist)
      lock_file = File.open(lock_path, "a")

      begin
        # Acquire exclusive lock (blocking with timeout)
        lock_file.flock_exclusive

        # Execute block with lock held
        yield
      ensure
        # Release lock and close file
        lock_file.flock_unlock
        lock_file.close
      end
    end

    private def create_backup
      backup_path = "#{@storage_path}.backup"
      File.copy(@storage_path, backup_path)
    end

    private def restore_from_backup
      backup_path = "#{@storage_path}.backup"
      File.copy(backup_path, @storage_path) if File.exists?(backup_path)
    end

    private def cleanup_old_backups
      # Keep only the most recent backup

      # Remove numbered backups if they exist
      10.times do |i|
        old_backup = "#{@storage_path}.backup.#{i}"
        File.delete(old_backup) if File.exists?(old_backup)
      end
    end
  end
end
