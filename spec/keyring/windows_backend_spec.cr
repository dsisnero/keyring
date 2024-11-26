require "../spec_helper"
require "../../src/keyring/windows_backend"

module Keyring
  describe WindowsBackend do
    backend = WindowsBackend.new
    test_service = "test_service"
    test_username = "test_user"
    test_password = "test_password123"

    describe ".available?" do
      it "returns true on Windows" do
        {% if flag?(:windows) %}
          WindowsBackend.available?.should be_true
        {% else %}
          WindowsBackend.available?.should be_false
        {% end %}
      end
    end

    {% if flag?(:windows) %}
      describe "#set_password" do
        it "stores a password" do
          backend.set_password(test_service, test_username, test_password).should be_nil
        end

        it "raises PasswordSetError for invalid inputs" do
          expect_raises(PasswordSetError) do
            backend.set_password("", "", "")
          end
        end
      end

      describe "#get_password" do
        it "retrieves a stored password" do
          backend.set_password(test_service, test_username, test_password)
          backend.get_password(test_service, test_username).should eq(test_password)
        end

        it "returns nil for non-existent credentials" do
          backend.get_password("nonexistent", "nonexistent").should be_nil
        end
      end

      describe "#delete_password" do
        it "deletes a stored password" do
          backend.set_password(test_service, test_username, test_password)
          backend.delete_password(test_service, test_username).should be_nil
          backend.get_password(test_service, test_username).should be_nil
        end

        it "raises PasswordDeleteError for non-existent credentials" do
          expect_raises(PasswordDeleteError) do
            backend.delete_password("nonexistent", "nonexistent")
          end
        end
      end

      describe "#get_credential" do
        it "returns a Credential object for stored password" do
          backend.set_password(test_service, test_username, test_password)
          credential = backend.get_credential(test_service, test_username)
          credential.should be_a(Credential)
          credential.try &.service.should eq(test_service)
          credential.try &.username.should eq(test_username)
          credential.try &.password.should eq(test_password)
        end

        it "returns nil for non-existent credentials" do
          backend.get_credential("nonexistent", "nonexistent").should be_nil
        end
      end

      describe "#list_credentials" do
        before_each do
          # Clean up any existing test credentials
          backend.list_credentials.each do |cred|
            if cred.service.starts_with?("test_")
              backend.delete_password(cred.service, cred.username)
            end
          end
        end

        it "lists all stored credentials" do
          # Store some test credentials
          backend.set_password(test_service, test_username, test_password)
          backend.set_password("#{test_service}_2", "#{test_username}_2", "password2")

          credentials = backend.list_credentials
          credentials.should be_a(Array(Credential))
          credentials.size.should be >= 2

          test_creds = credentials.select { |c| c.service.starts_with?("test_") }
          test_creds.size.should eq(2)

          # Clean up
          backend.delete_password(test_service, test_username)
          backend.delete_password("#{test_service}_2", "#{test_username}_2")
        end

        it "returns empty array when no credentials exist" do
          # Assuming we've cleaned up all test credentials in before_each
          credentials = backend.list_credentials.select { |c| c.service.starts_with?("test_") }
          credentials.should be_empty
        end
      end
    {% end %}
  end
end
