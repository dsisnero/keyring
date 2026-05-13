require "../spec_helper"

module IntegrationTestFakes
  class FakeUnavailableBackend < Keyring::Backend
    def self.available? : Bool
      false
    end

    def initialize; end

    def get_password(service : String, username : String) : String?
      nil
    end

    def set_password(service : String, username : String, password : String); end

    def delete_password(service : String, username : String); end

    def get_credential(service : String, username : String) : Keyring::Credential?
      nil
    end

    def list_credentials : Array(Keyring::Credential)
      [] of Keyring::Credential
    end
  end

  class FakeAvailableBackend < Keyring::Backend
    def self.available? : Bool
      true
    end

    def initialize; end

    def get_password(service : String, username : String) : String?
      nil
    end

    def set_password(service : String, username : String, password : String); end

    def delete_password(service : String, username : String); end

    def get_credential(service : String, username : String) : Keyring::Credential?
      nil
    end

    def list_credentials : Array(Keyring::Credential)
      [] of Keyring::Credential
    end
  end

  class FakeUnhealthyBackend < Keyring::Backend
    def self.available? : Bool
      true
    end

    def initialize; end

    def get_password(service : String, username : String) : String?
      nil
    end

    def set_password(service : String, username : String, password : String); end

    def delete_password(service : String, username : String); end

    def get_credential(service : String, username : String) : Keyring::Credential?
      nil
    end

    def list_credentials : Array(Keyring::Credential)
      raise Keyring::KeyringError.new("Simulated backend failure")
    end
  end
end

# End-to-end integration tests
describe "End-to-End Integration" do
  before_each do
    Keyring::Keyring.reset_backend_overrides
  end

  after_each do
    Keyring::Keyring.reset_backend_overrides
    ENV.delete("KEYRING_BACKEND")
    ENV.delete("XDG_DATA_HOME")
    ENV.delete("KEYRING_BACKEND_PRIORITY")
    ENV.delete("KEYRING_LOG_LEVEL")
    ENV.delete("KEYRING_ENCRYPTION_KEY")
    ENV.delete("KEYRING_ENCRYPT")
  end

  it "Basic workflow: stores, retrieves, and deletes credentials" do
    with_temp_dir("keyring-integration") do |dir|
      ENV["KEYRING_BACKEND"] = "FileBackend"
      ENV["XDG_DATA_HOME"] = dir
      # Ensure the keyring subdirectory exists before initialization
      Dir.mkdir_p(File.join(dir, "keyring"))
      keyring = Keyring::Keyring.new

      service = "test-service"
      username = "test-user"
      password = "test-password"

      # Initially password should not exist
      keyring.get_password(service, username).should be_nil

      # Store password
      keyring.set_password(service, username, password)
      keyring.get_password(service, username).should eq(password)

      # Delete password
      keyring.delete_password(service, username)
      keyring.get_password(service, username).should be_nil
    end
  end

  it "Multiple credentials: manages multiple credentials independently" do
    with_temp_dir("keyring-integration") do |dir|
      ENV["KEYRING_BACKEND"] = "FileBackend"
      ENV["XDG_DATA_HOME"] = dir
      Dir.mkdir_p(File.join(dir, "keyring"))
      keyring = Keyring::Keyring.new

      # Store multiple credentials
      keyring.set_password("service1", "user1", "pass1")
      keyring.set_password("service1", "user2", "pass2")
      keyring.set_password("service2", "user1", "pass3")

      # Retrieve each independently
      keyring.get_password("service1", "user1").should eq("pass1")
      keyring.get_password("service1", "user2").should eq("pass2")
      keyring.get_password("service2", "user1").should eq("pass3")

      # Update one credential
      keyring.set_password("service1", "user1", "newpass1")
      keyring.get_password("service1", "user1").should eq("newpass1")
      # Others unchanged
      keyring.get_password("service1", "user2").should eq("pass2")
      keyring.get_password("service2", "user1").should eq("pass3")

      # Delete one credential
      keyring.delete_password("service1", "user2")
      keyring.get_password("service1", "user2").should be_nil
      # Others still exist
      keyring.get_password("service1", "user1").should eq("newpass1")
      keyring.get_password("service2", "user1").should eq("pass3")
    end
  end
  it "Search functionality: searches credentials by service name" do
    with_temp_dir("keyring-integration") do |dir|
      ENV["KEYRING_BACKEND"] = "FileBackend"
      ENV["XDG_DATA_HOME"] = dir
      Dir.mkdir_p(File.join(dir, "keyring"))
      keyring = Keyring::Keyring.new

      # Create credentials with different service names
      keyring.set_password("email-service", "alice", "pass1")
      keyring.set_password("email-service", "bob", "pass2")
      keyring.set_password("database-service", "admin", "pass3")
      keyring.set_password("api-service", "alice", "pass4")

      # Search for "email" should return two credentials
      results = keyring.search("email")
      results.size.should eq(2)
      results.map(&.service).should contain("email-service")
      results.map(&.username).should contain("alice")
      results.map(&.username).should contain("bob")

      # Search for "service" should return all four (since all contain "service" in service name)
      results2 = keyring.search("service")
      results2.size.should eq(4)

      # Search for "alice" should return two credentials (username matches)
      results3 = keyring.search("alice")
      results3.size.should eq(2)
      results3.map(&.username).should contain("alice")
      results3.map(&.service).should contain("email-service")
      results3.map(&.service).should contain("api-service")

      # Search for "nonexistent" should return empty array
      keyring.search("nonexistent").size.should eq(0)
    end
  end
  it "Import/Export: exports and imports credentials" do
    with_temp_dir("keyring-integration") do |dir|
      ENV["KEYRING_BACKEND"] = "FileBackend"
      ENV["XDG_DATA_HOME"] = dir
      Dir.mkdir_p(File.join(dir, "keyring"))
      keyring = Keyring::Keyring.new

      # Create some credentials with metadata
      keyring.set_password("service1", "user1", "pass1")
      keyring.set_metadata("service1", "user1", "env", "prod")
      keyring.set_password("service2", "user2", "pass2")
      keyring.set_metadata("service2", "user2", "role", "admin")

      # Export to a temporary file
      with_temp_file("keyring-export") do |export_path|
        keyring.export_credentials(export_path)
        File.exists?(export_path).should be_true

        # Create a new keyring instance with a different storage directory
        # to simulate importing into a fresh keyring
        with_temp_dir("keyring-import") do |import_dir|
          ENV["XDG_DATA_HOME"] = import_dir
          Dir.mkdir_p(File.join(import_dir, "keyring"))
          keyring2 = Keyring::Keyring.new

          # Import credentials
          keyring2.import_credentials(export_path)

          # Verify imported credentials
          keyring2.get_password("service1", "user1").should eq("pass1")
          keyring2.get_password("service2", "user2").should eq("pass2")
          # Verify metadata
          cred1 = keyring2.get_credential("service1", "user1")
          cred1.should_not be_nil
          cred1.as(Keyring::Credential).metadata["env"].should eq("prod")
          cred2 = keyring2.get_credential("service2", "user2")
          cred2.should_not be_nil
          cred2.as(Keyring::Credential).metadata["role"].should eq("admin")
        end
      end
    end
  end
  it "Configuration: loads configuration from file" do
    with_temp_dir("keyring-integration") do |dir|
      # Create config file
      config_path = File.join(dir, "config.yaml")
      config_content = <<-YAML
        preferred_backend: FileBackend
        encrypt_passwords: false
        log_level: ERROR
        backend_priority:
          - FileBackend
        YAML
      File.write(config_path, config_content)

      # Set XDG_DATA_HOME to isolate storage
      ENV["XDG_DATA_HOME"] = dir
      Dir.mkdir_p(File.join(dir, "keyring"))

      # Initialize keyring with config file
      keyring = Keyring::Keyring.new(config_path)

      # Verify backend is FileBackend (should be selected due to config)
      keyring.backend.should be_a(Keyring::FileBackend)

      # Verify config values
      keyring.config.preferred_backend.should eq("FileBackend")
      keyring.config.encrypt_passwords?.should be_false
      keyring.config.log_level.should eq("ERROR")
      keyring.config.backend_priority.should eq(["FileBackend"])

      # Ensure basic functionality works with this config
      keyring.set_password("test", "user", "pass")
      keyring.get_password("test", "user").should eq("pass")
    end
  end
  it "Backend selection: uses preferred backend from config" do
    with_temp_dir("keyring-integration") do |dir|
      # Create config file specifying FileBackend
      config_path = File.join(dir, "config.yaml")
      File.write(config_path, <<-YAML
        preferred_backend: FileBackend
        encrypt_passwords: false
        log_level: ERROR
        backend_priority:
          - FileBackend
        YAML
      )

      # Set XDG_DATA_HOME to isolate storage
      ENV["XDG_DATA_HOME"] = dir
      Dir.mkdir_p(File.join(dir, "keyring"))

      # Initialize keyring with config file
      keyring = Keyring::Keyring.new(config_path)

      # Verify backend is FileBackend
      keyring.backend.should be_a(Keyring::FileBackend)

      # Also test that environment variable can override config
      ENV["KEYRING_BACKEND"] = "FileBackend"
      keyring2 = Keyring::Keyring.new(config_path)
      keyring2.backend.should be_a(Keyring::FileBackend)
    end
  end
  # Fake backends for testing fallback logic

  it "Backend selection: falls back to available backend" do
    # Override backend candidates with one unavailable and one available
    Keyring::Keyring.override_backend_candidates([IntegrationTestFakes::FakeUnavailableBackend, IntegrationTestFakes::FakeAvailableBackend])

    keyring = Keyring::Keyring.new
    keyring.backend.should be_a(IntegrationTestFakes::FakeAvailableBackend)
  end
  pending "Backend selection: switches backend on failure"
  pending "Encryption: encrypts passwords when configured"
  pending "Concurrent access: handles concurrent credential access"
  pending "Concurrent access: handles concurrent modifications"
  pending "Concurrent access: maintains data integrity under load"
  pending "Large datasets: handles 1000+ credentials efficiently"
  pending "Large datasets: searches large datasets quickly"
  pending "Large datasets: lists large datasets without timeout"
  pending "Error recovery: recovers from backend failures"
  pending "Error recovery: handles corrupted data gracefully"
  pending "Error recovery: provides helpful error messages"
end
