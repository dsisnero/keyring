require "../spec_helper"

module Keyring
  # Stub for non-Linux compilation
  {% unless flag?(:linux) %}
    class KWalletBackend < Backend
      def self.available? : Bool
        false
      end

      def initialize
      end

      def get_password(service : String, username : String) : String?
        nil
      end

      def set_password(service : String, username : String, password : String)
      end

      def delete_password(service : String, username : String)
      end

      def get_credential(service : String, username : String) : Credential?
        nil
      end

      def list_credentials : Array(Credential)
        [] of Credential
      end
    end
  {% end %}

  describe KWalletBackend do
    {% if flag?(:linux) %}
      it "can be constructed" do
        backend = KWalletBackend.new
        backend.should be_a(KWalletBackend)
      end

      it "implements abstract Backend methods" do
        backend = KWalletBackend.new
        backend.get_password("svc", "user").should be_nil
        backend.list_credentials.should be_a(Array(Credential))
      end
    {% else %}
      pending "KWalletBackend is Linux-only (compile-time)"
    {% end %}

    describe "self.available?" do
      it "returns false when qdbus is not installed" do
        {% if flag?(:linux) %}
          unless system("which qdbus > /dev/null 2>&1")
            KWalletBackend.available?.should be_false
          else
            KWalletBackend.available?.should be_a(Bool)
          end
        {% else %}
          KWalletBackend.available?.should be_false
        {% end %}
      end
    end

    {% if flag?(:linux) %}
      describe "D-Bus integration" do
        it "connects to wallet and performs get/set/delete cycle" do
          if KWalletBackend.available?
            backend = KWalletBackend.new
            svc = "kwallet-test-#{Random.rand(10_000)}"
            un = "test-user"

            backend.set_password(svc, un, "test-pass")
            backend.get_password(svc, un).should eq("test-pass")
            backend.delete_password(svc, un)
            backend.get_password(svc, un).should be_nil
          end
        end

        it "retrieves credential" do
          if KWalletBackend.available?
            backend = KWalletBackend.new
            svc = "kwallet-cred-#{Random.rand(10_000)}"
            un = "cred-user"

            backend.set_password(svc, un, "cred-pass")
            cred = backend.get_credential(svc, un)
            cred.should_not be_nil
            cred.try(&.password).should eq("cred-pass")
            backend.delete_password(svc, un)
          end
        end

        it "raises PasswordDeleteError for non-existent entry" do
          if KWalletBackend.available?
            backend = KWalletBackend.new
            expect_raises(PasswordDeleteError) do
              backend.delete_password("no-such-service", "no-such-user")
            end
          end
        end

        it "returns nil for non-existent password" do
          if KWalletBackend.available?
            backend = KWalletBackend.new
            backend.get_password("no-svc-99999", "no-user").should be_nil
          end
        end
      end
    {% else %}
      pending "D-Bus integration: connects to KWallet"
      pending "D-Bus integration: retrieves credential"
      pending "D-Bus integration: raises PasswordDeleteError for non-existent entry"
      pending "D-Bus integration: returns nil for non-existent password"
    {% end %}
  end
end
