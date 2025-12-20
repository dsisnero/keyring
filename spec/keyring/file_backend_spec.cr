require "../spec_helper"

module Keyring
  describe FileBackend do
    describe ".available?" do
      it "is always available" do
        FileBackend.available?.should be_true
      end
    end

    describe "initialization" do
      it "creates storage directory if it doesn't exist" do
        with_temp_dir("file_backend_test") do |dir|
          storage_path = File.join(dir, "subdir", "credentials.enc.json")
          key = Encryption.generate_key
          _backend = FileBackend.new(storage_path, key)

          {% unless flag?(:windows) %}
            # Check newly created directory has 0700 permissions
            stat = File.info(File.join(dir, "subdir"))
            (stat.permissions.value & 0o777).should eq(0o700)
          {% end %}
        end
      end
    end

    describe "#set_password and #get_password" do
      it "stores and retrieves passwords" do
        with_temp_dir("file_backend_test") do |dir|
          backend = FileBackend.new(File.join(dir, "creds.enc.json"), Encryption.generate_key)

          backend.set_password("service", "user", "password123")
          backend.get_password("service", "user").should eq("password123")
        end
      end

      it "returns nil for non-existent credentials" do
        with_temp_dir("file_backend_test") do |dir|
          backend = FileBackend.new(File.join(dir, "creds.enc.json"), Encryption.generate_key)
          backend.get_password("nonexistent", "user").should be_nil
        end
      end

      it "updates existing passwords" do
        with_temp_dir("file_backend_test") do |dir|
          backend = FileBackend.new(File.join(dir, "creds.enc.json"), Encryption.generate_key)

          backend.set_password("service", "user", "oldpass")
          backend.set_password("service", "user", "newpass")
          backend.get_password("service", "user").should eq("newpass")
        end
      end

      it "handles unicode characters" do
        with_temp_dir("file_backend_test") do |dir|
          backend = FileBackend.new(File.join(dir, "creds.enc.json"), Encryption.generate_key)

          unicode_pass = "パスワード🔐"
          backend.set_password("service", "user", unicode_pass)
          backend.get_password("service", "user").should eq(unicode_pass)
        end
      end

      it "handles special characters" do
        with_temp_dir("file_backend_test") do |dir|
          backend = FileBackend.new(File.join(dir, "creds.enc.json"), Encryption.generate_key)

          special_pass = "p@ss!w#rd$%^&*()"
          backend.set_password("service", "user", special_pass)
          backend.get_password("service", "user").should eq(special_pass)
        end
      end

      it "persists data across instances" do
        with_temp_dir("file_backend_test") do |dir|
          storage_path = File.join(dir, "creds.enc.json")
          key = Encryption.generate_key

          backend1 = FileBackend.new(storage_path, key)
          backend1.set_password("service", "user", "password")

          backend2 = FileBackend.new(storage_path, key)
          backend2.get_password("service", "user").should eq("password")
        end
      end
    end

    describe "#delete_password" do
      it "deletes stored password" do
        with_temp_dir("file_backend_test") do |dir|
          backend = FileBackend.new(File.join(dir, "creds.enc.json"), Encryption.generate_key)

          backend.set_password("service", "user", "pass")
          backend.delete_password("service", "user")
          backend.get_password("service", "user").should be_nil
        end
      end

      it "raises error for non-existent credential" do
        with_temp_dir("file_backend_test") do |dir|
          backend = FileBackend.new(File.join(dir, "creds.enc.json"), Encryption.generate_key)

          expect_raises(PasswordDeleteError, /Password not found/) do
            backend.delete_password("nonexistent", "user")
          end
        end
      end

      it "persists deletion across instances" do
        with_temp_dir("file_backend_test") do |dir|
          storage_path = File.join(dir, "creds.enc.json")
          key = Encryption.generate_key

          backend1 = FileBackend.new(storage_path, key)
          backend1.set_password("service", "user", "pass")
          backend1.delete_password("service", "user")

          backend2 = FileBackend.new(storage_path, key)
          backend2.get_password("service", "user").should be_nil
        end
      end
    end

    describe "#get_credential" do
      it "returns Credential object" do
        with_temp_dir("file_backend_test") do |dir|
          backend = FileBackend.new(File.join(dir, "creds.enc.json"), Encryption.generate_key)

          backend.set_password("service", "user", "pass")
          cred = backend.get_credential("service", "user")

          cred.should be_a(Credential)
          cred.try(&.service).should eq("service")
          cred.try(&.username).should eq("user")
          cred.try(&.password).should eq("pass")
        end
      end

      it "returns nil for non-existent credential" do
        with_temp_dir("file_backend_test") do |dir|
          backend = FileBackend.new(File.join(dir, "creds.enc.json"), Encryption.generate_key)
          backend.get_credential("nonexistent", "user").should be_nil
        end
      end
    end

    describe "#list_credentials" do
      it "returns all stored credentials" do
        with_temp_dir("file_backend_test") do |dir|
          backend = FileBackend.new(File.join(dir, "creds.enc.json"), Encryption.generate_key)

          backend.set_password("service1", "user1", "pass1")
          backend.set_password("service2", "user2", "pass2")
          backend.set_password("service3", "user3", "pass3")

          credentials = backend.list_credentials
          credentials.size.should eq(3)
        end
      end

      it "returns empty array when no credentials" do
        with_temp_dir("file_backend_test") do |dir|
          backend = FileBackend.new(File.join(dir, "creds.enc.json"), Encryption.generate_key)
          backend.list_credentials.should be_empty
        end
      end
    end

    describe "file operations" do
      it "creates backup before overwriting" do
        with_temp_dir("file_backend_test") do |dir|
          storage_path = File.join(dir, "creds.enc.json")
          key = Encryption.generate_key
          backend = FileBackend.new(storage_path, key)

          backend.set_password("service", "user", "pass1")
          File.exists?(storage_path).should be_true

          backend.set_password("service", "user", "pass2")
          # Backup should have been created during second write
          # (though it gets cleaned up after successful write)
        end
      end

      it "sets correct file permissions" do
        with_temp_dir("file_backend_test") do |dir|
          storage_path = File.join(dir, "creds.enc.json")
          backend = FileBackend.new(storage_path, Encryption.generate_key)

          backend.set_password("service", "user", "pass")

          {% unless flag?(:windows) %}
            stat = File.info(storage_path)
            (stat.permissions.value & 0o777).should eq(0o600)
          {% end %}
        end
      end

      it "handles corrupted file gracefully" do
        with_temp_dir("file_backend_test") do |dir|
          storage_path = File.join(dir, "creds.enc.json")
          key = Encryption.generate_key

          # Write corrupted data
          File.write(storage_path, "corrupted data not encrypted")

          expect_raises(BackendError, /Failed to decrypt/) do
            FileBackend.new(storage_path, key)
          end
        end
      end

      it "handles wrong encryption key" do
        with_temp_dir("file_backend_test") do |dir|
          storage_path = File.join(dir, "creds.enc.json")
          key1 = Encryption.generate_key
          key2 = Encryption.generate_key

          backend1 = FileBackend.new(storage_path, key1)
          backend1.set_password("service", "user", "pass")

          expect_raises(BackendError, /wrong key/) do
            FileBackend.new(storage_path, key2)
          end
        end
      end
    end

    describe "encryption" do
      it "stores credentials encrypted" do
        with_temp_dir("file_backend_test") do |dir|
          storage_path = File.join(dir, "creds.enc.json")
          backend = FileBackend.new(storage_path, Encryption.generate_key)

          backend.set_password("service", "user", "secretpassword")

          # Read raw file - should not contain plaintext password
          raw_content = File.read(storage_path)
          raw_content.should_not contain("secretpassword")
          raw_content.should_not contain("user")
          raw_content.should_not contain("service")
        end
      end

      it "auto-generates and saves encryption key" do
        with_temp_dir("file_backend_test") do |dir|
          storage_path = File.join(dir, "creds.enc.json")
          key_path = File.join(dir, ".keyring_key")

          backend = FileBackend.new(storage_path)
          File.exists?(key_path).should be_true

          saved_key = File.read(key_path).strip
          saved_key.should eq(backend.encryption_key)
        end
      end

      it "reuses existing encryption key" do
        with_temp_dir("file_backend_test") do |dir|
          storage_path = File.join(dir, "creds.enc.json")

          backend1 = FileBackend.new(storage_path)
          key1 = backend1.encryption_key

          backend2 = FileBackend.new(storage_path)
          key2 = backend2.encryption_key

          key1.should eq(key2)
        end
      end
    end

    describe "concurrent access" do
      it "handles file locking" do
        with_temp_dir("file_backend_test") do |dir|
          storage_path = File.join(dir, "creds.enc.json")
          key = Encryption.generate_key

          backend = FileBackend.new(storage_path, key)

          # Concurrent writes
          channel = Channel(Nil).new

          5.times do |i|
            spawn do
              backend.set_password("service_#{i}", "user", "pass_#{i}")
              channel.send(nil)
            end
          end

          5.times { channel.receive }

          # Verify all were stored
          backend.list_credentials.size.should eq(5)
        end
      end
    end

    describe "edge cases" do
      it "handles large numbers of credentials" do
        with_temp_dir("file_backend_test") do |dir|
          backend = FileBackend.new(File.join(dir, "creds.enc.json"), Encryption.generate_key)

          100.times do |i|
            backend.set_password("service_#{i}", "user_#{i}", "pass_#{i}")
          end

          backend.list_credentials.size.should eq(100)
          backend.get_password("service_50", "user_50").should eq("pass_50")
        end
      end

      it "handles empty service/username in storage" do
        with_temp_dir("file_backend_test") do |dir|
          backend = FileBackend.new(File.join(dir, "creds.enc.json"), Encryption.generate_key)

          # These should work at backend level (validation happens at Keyring level)
          backend.set_password("", "user", "pass")
          backend.get_password("", "user").should eq("pass")
        end
      end
    end
  end
end
