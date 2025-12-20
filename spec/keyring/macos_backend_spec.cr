require "../spec_helper"

{% if flag?(:darwin) %}
  require "../../src/keyring/macos_backend"
{% end %}

module Keyring
  {% if flag?(:darwin) %}
    describe MacOsKeyChainBackend do
      backend = MacOsKeyChainBackend.new
      test_service = "test_macos_service_#{Time.utc.to_unix}"
      test_username = "test_macos_user"
      test_password = "test_macos_pass123"

      # Clean up before and after tests
      before_each do
        begin
          backend.delete_password(test_service, test_username)
        rescue
          # Ignore if doesn't exist
        end
      end

      after_each do
        begin
          backend.delete_password(test_service, test_username)
        rescue
          # Ignore cleanup errors
        end
      end

      describe ".available?" do
        it "returns true on macOS" do
          MacOsKeyChainBackend.available?.should be_true
        end
      end

      describe "#set_password" do
        it "stores a password in macOS Keychain" do
          backend.set_password(test_service, test_username, test_password)
          password = backend.get_password(test_service, test_username)
          password.should eq(test_password)
        end

        it "updates existing password" do
          backend.set_password(test_service, test_username, "oldpass")
          backend.set_password(test_service, test_username, "newpass")
          password = backend.get_password(test_service, test_username)
          password.should eq("newpass")
        end
      end

      describe "#get_password" do
        it "retrieves a stored password" do
          backend.set_password(test_service, test_username, test_password)
          password = backend.get_password(test_service, test_username)
          password.should eq(test_password)
        end

        it "returns nil for non-existent credentials" do
          password = backend.get_password("nonexistent_macos_#{Time.utc.to_unix}", "nonexistent")
          password.should be_nil
        end

        it "handles special characters in password" do
          special_pass = "p@ss!w#rd$%^&*()"
          backend.set_password(test_service, test_username, special_pass)
          password = backend.get_password(test_service, test_username)
          password.should eq(special_pass)
        end
      end

      describe "#delete_password" do
        it "deletes a stored password" do
          backend.set_password(test_service, test_username, test_password)
          backend.delete_password(test_service, test_username)
          password = backend.get_password(test_service, test_username)
          password.should be_nil
        end

        it "raises PasswordDeleteError for non-existent credentials" do
          expect_raises(PasswordDeleteError) do
            backend.delete_password("nonexistent_macos_#{Time.utc.to_unix}", "nonexistent")
          end
        end
      end

      describe "#get_credential" do
        it "returns a Credential object" do
          backend.set_password(test_service, test_username, test_password)
          credential = backend.get_credential(test_service, test_username)

          credential.should be_a(Credential)
          credential.try(&.service).should eq(test_service)
          credential.try(&.username).should eq(test_username)
          credential.try(&.password).should eq(test_password)
        end

        it "returns nil for non-existent credentials" do
          credential = backend.get_credential("nonexistent_macos_#{Time.utc.to_unix}", "nonexistent")
          credential.should be_nil
        end
      end

      describe "#list_credentials" do
        it "returns array of credentials" do
          credentials = backend.list_credentials
          credentials.should be_a(Array(Credential))
        end

        it "includes credentials without passwords to avoid permission dialogs" do
          # Create a test credential
          backend.set_password(test_service, test_username, test_password)

          # List credentials
          credentials = backend.list_credentials

          # Find our test credential
          found = credentials.find do |c|
            c.service == test_service && c.username == test_username
          end

          found.should_not be_nil
          found.try(&.service).should eq(test_service)
          found.try(&.username).should eq(test_username)
          found.try(&.password).should be_nil # Passwords not included to avoid dialogs
        end

        it "allows fetching passwords separately" do
          backend.set_password(test_service, test_username, test_password)

          # List to get service/account pairs
          credentials = backend.list_credentials
          cred = credentials.find { |c| c.service == test_service }

          cred.should_not be_nil

          # Fetch password separately
          password = backend.get_password(cred.not_nil!.service, cred.not_nil!.username)
          password.should eq(test_password)
        end
      end

      describe "Integration tests" do
        it "handles multiple credentials" do
          backend.set_password("#{test_service}_1", "user1", "pass1")
          backend.set_password("#{test_service}_2", "user2", "pass2")

          backend.get_password("#{test_service}_1", "user1").should eq("pass1")
          backend.get_password("#{test_service}_2", "user2").should eq("pass2")

          # Clean up
          backend.delete_password("#{test_service}_1", "user1")
          backend.delete_password("#{test_service}_2", "user2")
        end

        it "handles unicode characters" do
          unicode_pass = "パスワード🔐"
          backend.set_password(test_service, test_username, unicode_pass)
          password = backend.get_password(test_service, test_username)
          password.should eq(unicode_pass)
        end
      end
    end
  {% end %}
end
