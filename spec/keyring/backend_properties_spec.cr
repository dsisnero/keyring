require "../spec_helper"

module Keyring
  class SchemeTestBackend < Backend
    include SchemeSelectable

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

  describe SchemeSelectable do
    it "default scheme maps service and username keys" do
      backend = SchemeTestBackend.new
      result = backend._query("my-service", "my-user")
      result["service"].should eq("my-service")
      result["username"].should eq("my-user")
    end

    it "default scheme handles nil username" do
      backend = SchemeTestBackend.new
      result = backend._query("my-service")
      result["service"].should eq("my-service")
      result.has_key?("username").should be_false
    end

    it "KeePassXC scheme uses Title and UserName keys" do
      backend = SchemeTestBackend.new
      backend.scheme = "KeePassXC"
      result = backend._query("app", "user")
      result["Title"].should eq("app")
      result["UserName"].should eq("user")
    end

    it "merges extra keyword arguments" do
      backend = SchemeTestBackend.new
      result = backend._query("svc", "usr", extra: "value")
      result["service"].should eq("svc")
      result["extra"].should eq("value")
    end
  end

  class PropsTestBackend < Backend
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

  describe Backend do
    describe "#set_properties_from_env" do
      it "reads KEYRING_PROPERTY_* env vars" do
        with_env("KEYRING_PROPERTY_collection", "session") do
          with_env("KEYRING_PROPERTY_timeout", "30") do
            backend = PropsTestBackend.new
            backend.set_properties_from_env
            backend["collection"].should eq("session")
            backend["timeout"].should eq("30")
          end
        end
      end

      it "returns nil when no properties set" do
        backend = PropsTestBackend.new
        backend["nonexistent"].should be_nil
      end
    end

    describe "#with_properties" do
      it "creates a copy with additional properties" do
        backend = PropsTestBackend.new
        alt = backend.with_properties(collection: "session", timeout: "30")
        alt["collection"].should eq("session")
        alt["timeout"].should eq("30")
        backend["collection"].should be_nil
      end

      it "keeps existing properties in copy" do
        with_env("KEYRING_PROPERTY_existing", "original") do
          backend = PropsTestBackend.new
          backend.set_properties_from_env
          alt = backend.with_properties(new_prop: "new-value")
          alt["existing"].should eq("original")
          alt["new_prop"].should eq("new-value")
          backend["new_prop"].should be_nil
        end
      end
    end
  end
end
