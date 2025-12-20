require "../spec_helper"
require "../../src/keyring/keyring"

module Keyring
  # Fake backends for testing selection logic
  class FakeHealthyA < Backend
    def self.available? : Bool
      true
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

  class FakeHealthyB < Backend
    def self.available? : Bool
      true
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

  class FakeUnhealthy < Backend
    def self.available? : Bool
      true
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
      raise KeyringError.new("simulated health check failure")
    end
  end

  class FakeUnavailable < Backend
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

  describe "Backend priority and health-check" do
    after_each do
      # Reset overrides and environment
      Keyring.reset_backend_overrides
      ENV.delete("KEYRING_BACKEND_PRIORITY")
      ENV.delete("KEYRING_BACKEND")
    end

    it "honors priority ordering when multiple backends are healthy" do
      # Order candidates arbitrarily, then set priority to select B first
      Keyring.override_backend_candidates([FakeHealthyA, FakeHealthyB])
      ENV["KEYRING_BACKEND_PRIORITY"] = "FakeHealthyB,FakeHealthyA"

      keyring = Keyring.new
      keyring.backend.class.should eq(FakeHealthyB)
    end

    it "falls back to next healthy backend when the first fails health check" do
      # First candidate is unhealthy (list_credentials raises), second is healthy
      Keyring.override_backend_candidates([FakeUnhealthy, FakeHealthyA])
      # No priority -> use given order

      keyring = Keyring.new
      keyring.backend.class.should eq(FakeHealthyA)
    end

    it "skips unavailable backends regardless of priority" do
      Keyring.override_backend_candidates([FakeUnavailable, FakeHealthyA])
      ENV["KEYRING_BACKEND_PRIORITY"] = "FakeUnavailable,FakeHealthyA"

      keyring = Keyring.new
      keyring.backend.class.should eq(FakeHealthyA)
    end

    it "uses preferred backend if available (even if lower priority)" do
      Keyring.override_backend_candidates([FakeHealthyA, FakeHealthyB])
      ENV["KEYRING_BACKEND_PRIORITY"] = "FakeHealthyA,FakeHealthyB"
      ENV["KEYRING_BACKEND"] = "FakeHealthyB"

      keyring = Keyring.new
      keyring.backend.class.should eq(FakeHealthyB)
    end
  end
end
