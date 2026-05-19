require "../spec_helper"

module Keyring
  describe "Metadata contract" do
    before_each do
      Keyring.reset_backend_overrides
    end

    after_each do
      Keyring.reset_backend_overrides
      ENV.delete("KEYRING_BACKEND")
      ENV.delete("XDG_DATA_HOME")
    end

    it "persists metadata with FileBackend via Keyring API" do
      dir = "/tmp/keyring-meta-#{Random.rand(1_000_000)}"
      Dir.mkdir_p(dir)
      Dir.mkdir_p(File.join(dir, "keyring_cr"))
      # Force FileBackend via environment and ensure it uses our temp directory
      ENV["KEYRING_BACKEND"] = "FileBackend"
      ENV["XDG_DATA_HOME"] = dir

      # Create a keyring instance (will pick FileBackend)
      keyring = Keyring.new
      service = "meta-svc-#{Random.rand(10_000)}"
      user = "meta-user"

      keyring.set_password(service, user, "pw")
      keyring.set_metadata(service, user, "env", "dev")
      keyring.set_metadata(service, user, "owner", "teamA")

      # New keyring instance to ensure persistence across reload
      keyring2 = Keyring.new
      cred = keyring2.get_credential(service, user)

      cred.should_not be_nil
      cred = cred.as(Credential)
      cred.metadata["env"].should eq("dev")
      cred.metadata["owner"].should eq("teamA")
    end

    it "sets and retrieves metadata with MockBackend (in-memory)" do
      # Override candidates so MockBackend is selected
      Keyring.override_backend_candidates([MockBackend.as(Backend.class)])
      keyring = Keyring.new
      service = "meta-mock-#{Random.rand(10_000)}"
      user = "mock-user"

      keyring.set_password(service, user, "pw")
      keyring.set_metadata(service, user, "env", "test")
      keyring.set_metadata(service, user, "version", "1.0")

      cred = keyring.get_credential(service, user)
      cred.should_not be_nil
      cred = cred.as(Credential)
      cred.metadata["env"].should eq("test")
      cred.metadata["version"].should eq("1.0")
    end
  end
end
