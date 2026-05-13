require "../spec_helper"

module Keyring
  # Fake backends for testing the chainer
  class FakeAlpha < Backend
    def self.available? : Bool
      true
    end

    def get_password(service : String, username : String) : String?
      "alpha:#{service}:#{username}"
    end

    def set_password(service : String, username : String, password : String)
      # succeeds
    end

    def delete_password(service : String, username : String)
      # succeeds
    end

    def get_credential(service : String, username : String) : Credential?
      Credential.new(service: service, username: username, password: "alpha-cred")
    end

    def list_credentials : Array(Credential)
      [Credential.new(service: "alpha-svc", username: "a", password: "p1")]
    end
  end

  class FakeBeta < Backend
    def self.available? : Bool
      true
    end

    def get_password(service : String, username : String) : String?
      nil
    end

    def set_password(service : String, username : String, password : String)
      # succeeds
    end

    def delete_password(service : String, username : String)
      raise PasswordDeleteError.new("beta cannot delete")
    end

    def get_credential(service : String, username : String) : Credential?
      nil
    end

    def list_credentials : Array(Credential)
      [Credential.new(service: "beta-svc", username: "b", password: "p2")]
    end
  end

  class FakeGamma < Backend
    def self.available? : Bool
      true
    end

    def get_password(service : String, username : String) : String?
      "gamma:#{service}:#{username}"
    end

    def set_password(service : String, username : String, password : String)
      raise PasswordSetError.new("gamma cannot set")
    end

    def delete_password(service : String, username : String)
      # succeeds
    end

    def get_credential(service : String, username : String) : Credential?
      Credential.new(service: service, username: username, password: "gamma-cred")
    end

    def list_credentials : Array(Credential)
      [Credential.new(service: "gamma-svc", username: "g", password: "p3")]
    end
  end

  describe ChainerBackend do
    describe "constructor" do
      it "accepts pre-instantiated backends" do
        chainer = ChainerBackend.new(FakeAlpha.new, FakeBeta.new)
        chainer.backends.size.should eq(2)
      end

      it "is not auto-detectable (requires explicit backends)" do
        ChainerBackend.available?.should be_false
      end
    end

    describe "get_password" do
      it "returns first non-nil result from chained backends" do
        chainer = ChainerBackend.new(FakeBeta.new, FakeAlpha.new)
        pw = chainer.get_password("svc", "user")
        pw.should eq("alpha:svc:user")
      end

      it "returns nil when all backends return nil" do
        chainer = ChainerBackend.new(FakeBeta.new, FakeBeta.new)
        chainer.get_password("svc", "user").should be_nil
      end

      it "skips failed backends and continues" do
        err = FailBackend.new("get error")
        chainer = ChainerBackend.new(err, FakeAlpha.new)
        pw = chainer.get_password("svc", "user")
        pw.should eq("alpha:svc:user")
      end

      it "returns nil when all backends fail" do
        err1 = FailBackend.new("error1")
        err2 = FailBackend.new("error2")
        chainer = ChainerBackend.new(err1, err2)
        chainer.get_password("svc", "user").should be_nil
      end
    end

    describe "set_password" do
      it "succeeds if any backend succeeds" do
        alpha = FakeAlpha.new
        gamma = FakeGamma.new
        chainer = ChainerBackend.new(gamma, alpha)
        chainer.set_password("svc", "user", "pass")
      end

      it "raises when all backends fail" do
        gamma1 = FakeGamma.new
        gamma2 = FakeGamma.new
        chainer = ChainerBackend.new(gamma1, gamma2)
        expect_raises(PasswordSetError) do
          chainer.set_password("svc", "user", "pass")
        end
      end

      it "returns after first successful set" do
        alpha = FakeAlpha.new
        gamma = FakeGamma.new
        chainer = ChainerBackend.new(alpha, gamma)
        chainer.set_password("svc", "user", "pass")
      end
    end

    describe "delete_password" do
      it "succeeds if any backend succeeds" do
        alpha = FakeAlpha.new
        beta = FakeBeta.new
        chainer = ChainerBackend.new(beta, alpha)
        chainer.delete_password("svc", "user")
      end

      it "raises when all backends fail" do
        beta1 = FakeBeta.new
        beta2 = FakeBeta.new
        chainer = ChainerBackend.new(beta1, beta2)
        expect_raises(PasswordDeleteError) do
          chainer.delete_password("svc", "user")
        end
      end
    end

    describe "get_credential" do
      it "returns first non-nil credential" do
        chainer = ChainerBackend.new(FakeBeta.new, FakeAlpha.new)
        cred = chainer.get_credential("svc", "user")
        cred.should_not be_nil
        cred.as(Credential).password.should eq("alpha-cred")
      end

      it "returns nil when all backends return nil" do
        chainer = ChainerBackend.new(FakeBeta.new, FakeBeta.new)
        chainer.get_credential("svc", "user").should be_nil
      end
    end

    describe "list_credentials" do
      it "merges results from all backends" do
        chainer = ChainerBackend.new(FakeAlpha.new, FakeBeta.new, FakeGamma.new)
        creds = chainer.list_credentials
        creds.size.should eq(3)
        services = creds.map(&.service).sort
        services.should eq(["alpha-svc", "beta-svc", "gamma-svc"])
      end

      it "skips backends that fail on list" do
        err = FailBackend.new("list error")
        chainer = ChainerBackend.new(FakeAlpha.new, err)
        creds = chainer.list_credentials
        creds.size.should eq(1)
      end

      it "returns empty array when all backends fail" do
        err1 = FailBackend.new("e1")
        err2 = FailBackend.new("e2")
        chainer = ChainerBackend.new(err1, err2)
        chainer.list_credentials.should be_empty
      end
    end
  end
end
