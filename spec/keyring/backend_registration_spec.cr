require "../spec_helper"
require "../../src/keyring/keyring"

module Keyring
  # Test backends for registration system
  class RegTestBackendA < Backend
    def self.available? : Bool
      true
    end

    def initialize; end

    def get_password(service : String, username : String) : String?
      "password-a"
    end

    def set_password(service : String, username : String, password : String); end

    def delete_password(service : String, username : String); end

    def get_credential(service : String, username : String) : Credential?
      Credential.new(service: service, username: username, password: "password-a")
    end

    def list_credentials : Array(Credential)
      [Credential.new(service: "svc", username: "usr", password: "x")]
    end
  end

  class RegTestBackendB < Backend
    def self.available? : Bool
      true
    end

    def initialize; end

    def get_password(service : String, username : String) : String?
      "password-b"
    end

    def set_password(service : String, username : String, password : String); end

    def delete_password(service : String, username : String); end

    def get_credential(service : String, username : String) : Credential?
      Credential.new(service: service, username: username, password: "password-b")
    end

    def list_credentials : Array(Credential)
      [] of Credential
    end
  end

  class RegTestUnavailableBackend < Backend
    def self.available? : Bool
      false
    end

    def initialize; end

    def get_password(service : String, username : String) : String?
      nil
    end

    def set_password(service : String, username : String, password : String); end

    def delete_password(service : String, username : String); end

    def get_credential(service : String, username : String) : Credential?
      nil
    end

    def list_credentials : Array(Credential)
      [] of Credential
    end
  end

  describe Backend do
    describe ".register" do
      after_each do
        Backend.clear_registry
      end

      it "registers a backend class" do
        Backend.register(RegTestBackendA)
        Backend.registry.should contain(RegTestBackendA)
      end

      it "deduplicates registrations" do
        3.times { Backend.register(RegTestBackendA) }
        Backend.registry.select { |k| k == RegTestBackendA }.size.should eq(1)
      end

      it "supports multiple backends" do
        Backend.register(RegTestBackendA)
        Backend.register(RegTestBackendB)
        registry = Backend.registry
        registry.should contain(RegTestBackendA)
        registry.should contain(RegTestBackendB)
      end
    end

    describe ".registry" do
      after_each do
        Backend.clear_registry
      end

      it "returns empty array by default" do
        Backend.registry.should be_a(Array(Backend.class))
      end

      it "returns registered backends in registration order" do
        Backend.register(RegTestBackendA)
        Backend.register(RegTestBackendB)
        registry = Backend.registry
        registry[0].should eq(RegTestBackendA)
        registry[1].should eq(RegTestBackendB)
      end
    end

    describe ".clear_registry" do
      after_each do
        Backend.clear_registry
      end

      it "clears all registered backends" do
        Backend.register(RegTestBackendA)
        Backend.register(RegTestBackendB)
        Backend.clear_registry
        Backend.registry.should be_empty
      end
    end
  end

  describe ".get_all_keyring" do
    after_each do
      Backend.clear_registry
    end

    it "returns instances of all viable registered backends" do
      Backend.register(RegTestBackendA)
      Backend.register(RegTestBackendB)
      Backend.register(RegTestUnavailableBackend)

      Keyring.override_backend_candidates([
        RegTestBackendA,
        RegTestBackendB,
        RegTestUnavailableBackend,
      ] of Backend.class)

      all = Keyring.get_all_keyring
      all.size.should eq(2)
      all.map(&.class).should contain(RegTestBackendA)
      all.map(&.class).should contain(RegTestBackendB)
    ensure
      Keyring.reset_backend_overrides
    end

    it "excludes unavailable backends" do
      Keyring.override_backend_candidates([RegTestUnavailableBackend] of Backend.class)

      all = Keyring.get_all_keyring
      all.should be_empty
    ensure
      Keyring.reset_backend_overrides
    end
  end
end
