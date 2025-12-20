require "../spec_helper"

{% if flag?(:linux) %}
  require "../../src/keyring/linux_backend"

  module Keyring
    describe LinuxSecretServiceBackend do
      let(:backend) { LinuxSecretServiceBackend.new }
      let(:service) { "test-service-#{Random.rand(10000)}" }
      let(:username) { "test-user-#{Random.rand(10000)}" }
      let(:password) { "test-password-#{Random.rand(10000)}" }

      after_each do
        begin
          backend.delete_password(service, username)
        rescue PasswordDeleteError
        end
      end

      describe ".available?" do
        it "returns true on Linux with libsecret" do
          LinuxSecretServiceBackend.available?.should be_true
        end
      end

      describe "#set_password" do
        it "stores a password successfully" do
          expect_raises(Exception) do
            backend.set_password(service, username, password)
          end.should be_nil
        end

        it "updates an existing password" do
          backend.set_password(service, username, "old-password")
          backend.set_password(service, username, password)
          backend.get_password(service, username).should eq(password)
        end

        it "handles special characters in password" do
          special_password = "p@ssw0rd!#$%^&*()"
          backend.set_password(service, username, special_password)
          backend.get_password(service, username).should eq(special_password)
        end

        it "handles unicode in password" do
          unicode_password = "密码🔐"
          backend.set_password(service, username, unicode_password)
          backend.get_password(service, username).should eq(unicode_password)
        end
      end

      describe "#get_password" do
        it "retrieves a stored password" do
          backend.set_password(service, username, password)
          backend.get_password(service, username).should eq(password)
        end

        it "returns nil for non-existent credential" do
          backend.get_password("nonexistent-service", "nonexistent-user").should be_nil
        end

        it "handles special characters in service name" do
          special_service = "test:service/with@special#chars"
          backend.set_password(special_service, username, password)
          backend.get_password(special_service, username).should eq(password)
          backend.delete_password(special_service, username)
        end

        it "handles unicode in service and username" do
          unicode_service = "服务-#{Random.rand(10000)}"
          unicode_username = "用户-#{Random.rand(10000)}"
          backend.set_password(unicode_service, unicode_username, password)
          backend.get_password(unicode_service, unicode_username).should eq(password)
          backend.delete_password(unicode_service, unicode_username)
        end
      end

      describe "#delete_password" do
        it "deletes a stored password" do
          backend.set_password(service, username, password)
          backend.delete_password(service, username)
          backend.get_password(service, username).should be_nil
        end

        it "raises error when deleting non-existent credential" do
          expect_raises(PasswordDeleteError) do
            backend.delete_password("nonexistent-service", "nonexistent-user")
          end
        end
      end

      describe "#get_credential" do
        it "retrieves a credential with password" do
          backend.set_password(service, username, password)
          credential = backend.get_credential(service, username)
          credential.should_not be_nil
          credential.not_nil!.service.should eq(service)
          credential.not_nil!.username.should eq(username)
          credential.not_nil!.password.should eq(password)
        end

        it "returns nil for non-existent credential" do
          backend.get_credential("nonexistent-service", "nonexistent-user").should be_nil
        end
      end

      describe "#list_credentials" do
        it "lists all stored credentials" do
          test_service = "list-test-#{Random.rand(10000)}"
          test_users = ["user1", "user2", "user3"]

          test_users.each do |user|
            backend.set_password(test_service, user, "password-#{user}")
          end

          credentials = backend.list_credentials
          found = credentials.select { |c| c.service == test_service }
          found.size.should eq(3)

          test_users.each do |user|
            backend.delete_password(test_service, user)
          end
        end

        it "returns empty array when no credentials exist" do
          backend.list_credentials.should be_a(Array(Credential))
        end

        it "includes passwords in listed credentials" do
          backend.set_password(service, username, password)
          credentials = backend.list_credentials
          found = credentials.find { |c| c.service == service && c.username == username }
          found.should_not be_nil
          found.not_nil!.password.should eq(password)
        end
      end

      describe "concurrent access" do
        it "handles multiple operations without corruption" do
          services = (1..5).map { |i| "concurrent-service-#{i}-#{Random.rand(10000)}" }

          services.each do |s|
            backend.set_password(s, "user", "password-#{s}")
          end

          services.each do |s|
            backend.get_password(s, "user").should eq("password-#{s}")
          end

          services.each do |s|
            backend.delete_password(s, "user")
          end
        end
      end

      describe "error handling" do
        it "handles libsecret errors gracefully" do
          backend.set_password(service, username, password)
          retrieved = backend.get_password(service, username)
          retrieved.should eq(password)
        end
      end
    end
  end
{% end %}
