require "../spec_helper"

module Keyring
  describe NullBackend do
    it "returns nil for get_password" do
      backend = NullBackend.new
      backend.get_password("any-service", "any-user").should be_nil
    end

    it "does nothing on set_password" do
      backend = NullBackend.new
      backend.set_password("svc", "user", "pass")
      backend.get_password("svc", "user").should be_nil
    end

    it "does nothing on delete_password" do
      backend = NullBackend.new
      backend.delete_password("svc", "user")
    end

    it "returns nil for get_credential" do
      backend = NullBackend.new
      backend.get_credential("svc", "user").should be_nil
    end

    it "returns empty array for list_credentials" do
      backend = NullBackend.new
      backend.list_credentials.should be_empty
    end

    it "is always available" do
      NullBackend.available?.should be_true
    end
  end

  describe FailBackend do
    it "raises NoBackendError on get_password" do
      backend = FailBackend.new
      expect_raises(NoBackendError) do
        backend.get_password("svc", "user")
      end
    end

    it "raises NoBackendError on set_password" do
      backend = FailBackend.new
      expect_raises(NoBackendError) do
        backend.set_password("svc", "user", "pass")
      end
    end

    it "raises NoBackendError on delete_password" do
      backend = FailBackend.new
      expect_raises(NoBackendError) do
        backend.delete_password("svc", "user")
      end
    end

    it "raises NoBackendError on get_credential" do
      backend = FailBackend.new
      expect_raises(NoBackendError) do
        backend.get_credential("svc", "user")
      end
    end

    it "raises NoBackendError on list_credentials" do
      backend = FailBackend.new
      expect_raises(NoBackendError) do
        backend.list_credentials
      end
    end

    it "uses default error message" do
      backend = FailBackend.new
      backend.error_message.should contain("No recommended backend")
    end

    it "supports custom error message" do
      backend = FailBackend.new("custom error")
      backend.error_message.should eq("custom error")
    end

    it "is always available" do
      FailBackend.available?.should be_true
    end
  end

  describe "module-level keyring=/keyring" do
    after_each do
      # Reset class-level keyring to nil so tests are isolated
      ::Keyring::Keyring.keyring = NullBackend.new
    end

    it "keyring returns a keyring with auto-detected backend" do
      kr = ::Keyring::Keyring.keyring
      kr.backend.should_not be_nil
    end

    it "keyring= allows setting a custom backend" do
      null = NullBackend.new
      ::Keyring::Keyring.keyring = null
      kr = ::Keyring::Keyring.keyring
      kr.backend.should be_a(NullBackend)
    end

    it "keyring= with FailBackend propagates errors on use" do
      fail = FailBackend.new("test error")
      ::Keyring::Keyring.keyring = fail
      kr = ::Keyring::Keyring.keyring
      expect_raises(NoBackendError, "test error") do
        kr.get_password("svc", "user")
      end
    end

    it "keyring= with NullBackend returns nil for all operations" do
      ::Keyring::Keyring.keyring = NullBackend.new
      kr = ::Keyring::Keyring.keyring
      kr.get_password("svc", "user").should be_nil
      kr.set_password("svc", "user", "pass")
      kr.list_credentials.should be_empty
    end
  end
end
