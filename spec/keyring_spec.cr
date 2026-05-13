require "./spec_helper"

describe Keyring do
  it "has a version number" do
    Keyring::VERSION.should_not be_nil
    Keyring::VERSION.should be_a(String)
  end

  describe "::Keyring" do
    it "initializes with default config" do
      keyring = Keyring::Keyring.new
      keyring.should be_a(Keyring::Keyring)
      keyring.backend.should be_a(Keyring::Backend)
      keyring.config.should be_a(Keyring::Config)
    end

    it "selects appropriate backend for platform" do
      keyring = Keyring::Keyring.new

      {% if flag?(:darwin) %}
        keyring.backend.should be_a(Keyring::MacOsKeyChainBackend)
      {% elsif flag?(:windows) %}
        keyring.backend.should be_a(Keyring::WindowsBackend)
      {% elsif flag?(:linux) %}
        keyring.backend.should be_a(Keyring::LinuxSecretServiceBackend)
      {% else %}
        keyring.backend.should be_a(Keyring::FileBackend)
      {% end %}
    end

    describe "validation" do
      it "raises error for empty service name" do
        keyring = Keyring::Keyring.new

        expect_raises(Keyring::KeyringError, /Service name cannot be empty/) do
          keyring.get_password("", "user")
        end
      end

      it "raises error for empty username" do
        keyring = Keyring::Keyring.new

        expect_raises(Keyring::KeyringError, /Username cannot be empty/) do
          keyring.get_password("service", "")
        end
      end

      it "raises error for empty password" do
        keyring = Keyring::Keyring.new

        expect_raises(Keyring::KeyringError, /Password cannot be empty/) do
          keyring.set_password("service", "user", "")
        end
      end
    end

    describe "#update_password" do
      it "updates existing password" do
        keyring = Keyring::Keyring.new
        service = "upd-svc-#{Random.rand(10_000)}"
        user = "upd-user"
        keyring.set_password(service, user, "old-pass")
        keyring.get_password(service, user).should eq("old-pass")

        keyring.update_password(service, user, "new-pass")
        keyring.get_password(service, user).should eq("new-pass")

        keyring.delete_password(service, user)
      end

      it "raises error if credential doesn't exist" do
        keyring = Keyring::Keyring.new
        expect_raises(Keyring::KeyringError, /not found/) do
          keyring.update_password("no-svc", "no-user", "pass")
        end
      end

      it "validates parameters" do
        keyring = Keyring::Keyring.new
        expect_raises(Keyring::KeyringError, /empty/) do
          keyring.update_password("", "user", "pass")
        end
        expect_raises(Keyring::KeyringError, /empty/) do
          keyring.update_password("svc", "", "pass")
        end
        expect_raises(Keyring::KeyringError, /empty/) do
          keyring.update_password("svc", "user", "")
        end
      end
    end
  end
end
