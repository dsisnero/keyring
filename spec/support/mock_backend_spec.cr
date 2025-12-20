require "../spec_helper"

module Keyring
  describe MockBackend do
    backend = MockBackend.new

    before_each do
      backend.clear
    end

    describe ".available?" do
      it "returns true" do
        MockBackend.available?.should be_true
      end
    end

    describe "#set_password and #get_password" do
      it "stores and retrieves passwords" do
        backend.set_password("service", "user", "pass")
        backend.get_password("service", "user").should eq("pass")
      end

      it "returns nil for non-existent credential" do
        backend.get_password("nonexistent", "user").should be_nil
      end

      it "updates existing password" do
        backend.set_password("service", "user", "oldpass")
        backend.set_password("service", "user", "newpass")
        backend.get_password("service", "user").should eq("newpass")
      end
    end

    describe "#delete_password" do
      it "deletes stored password" do
        backend.set_password("service", "user", "pass")
        backend.delete_password("service", "user")
        backend.get_password("service", "user").should be_nil
      end

      it "raises error for non-existent password" do
        expect_raises(PasswordDeleteError) do
          backend.delete_password("nonexistent", "user")
        end
      end
    end

    describe "#get_credential" do
      it "returns credential object" do
        backend.set_password("service", "user", "pass")
        cred = backend.get_credential("service", "user")

        cred.should be_a(Credential)
        cred.try(&.service).should eq("service")
        cred.try(&.username).should eq("user")
        cred.try(&.password).should eq("pass")
      end

      it "returns nil for non-existent credential" do
        backend.get_credential("nonexistent", "user").should be_nil
      end
    end

    describe "#list_credentials" do
      it "returns all stored credentials" do
        backend.set_password("service1", "user1", "pass1")
        backend.set_password("service2", "user2", "pass2")
        backend.set_password("service3", "user3", "pass3")

        credentials = backend.list_credentials
        credentials.size.should eq(3)
      end

      it "returns empty array when no credentials" do
        backend.list_credentials.should be_empty
      end
    end

    describe "#clear" do
      it "removes all credentials" do
        backend.set_password("service1", "user1", "pass1")
        backend.set_password("service2", "user2", "pass2")

        backend.clear
        backend.size.should eq(0)
        backend.list_credentials.should be_empty
      end
    end

    describe "#size" do
      it "returns number of stored credentials" do
        backend.size.should eq(0)
        backend.set_password("service", "user", "pass")
        backend.size.should eq(1)
        backend.set_password("service2", "user2", "pass2")
        backend.size.should eq(2)
      end
    end
  end
end
