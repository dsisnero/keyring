require "../../src/keyring"

module TestHelpers
  extend self

  # Create a test credential with common values
  def create_test_credential(
    service : String = "test_service",
    username : String = "test_user",
    password : String = "test_password_123",
  ) : Keyring::Credential
    Keyring::Credential.new(service, username, password)
  end

  # Create a test config
  def create_test_config(
    encrypt : Bool = false,
    backend : String? = nil,
  ) : Keyring::Config
    config = Keyring::Config.new
    config.encrypt_passwords = encrypt
    config.encryption_key = Keyring::Encryption.generate_key if encrypt
    config.preferred_backend = backend if backend
    config.log_level = "ERROR" # Quiet during tests
    config
  end

  # Generate a unique service name for testing
  def unique_service(prefix : String = "test") : String
    "#{prefix}_#{Time.utc.to_unix}_#{Random.rand(1000)}"
  end

  # Generate a unique username for testing
  def unique_username(prefix : String = "user") : String
    "#{prefix}_#{Random.rand(10000)}"
  end

  # Clean up test credentials by prefix
  def cleanup_test_credentials(keyring : Keyring::Keyring, prefix : String = "test_")
    credentials = keyring.list_credentials
    credentials.each do |cred|
      if cred.service.starts_with?(prefix)
        begin
          keyring.delete_password(cred.service, cred.username)
        rescue
          # Ignore errors during cleanup
        end
      end
    end
  end

  # Temporary file helper
  def with_temp_file(prefix : String = "keyring_test", &)
    path = "/tmp/#{prefix}_#{Time.utc.to_unix}.tmp"
    begin
      yield path
    ensure
      File.delete(path) if File.exists?(path)
    end
  end

  # Temporary directory helper
  def with_temp_dir(prefix : String = "keyring_test", &)
    path = "/tmp/#{prefix}_#{Time.utc.to_unix}"
    begin
      Dir.mkdir_p(path)
      yield path
    ensure
      FileUtils.rm_rf(path) if Dir.exists?(path)
    end
  end

  # Set environment variable for duration of block, restore after
  def with_env(key : String, value : String?, &)
    old = ENV[key]?
    begin
      if value
        ENV[key] = value
      else
        ENV.delete(key)
      end
      yield
    ensure
      if old
        ENV[key] = old
      else
        ENV.delete(key)
      end
    end
  end
end

# Make helpers available in specs
include TestHelpers
