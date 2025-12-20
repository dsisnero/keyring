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
      pending "updates existing password"
      pending "raises error if credential doesn't exist"
      pending "validates parameters"
    end
  end
end
