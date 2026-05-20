require "../spec_helper"

module Keyring
  describe Credential do
    describe ".new" do
      it "creates credential with required fields" do
        cred = Credential.new("MyService", "myuser", "mypass")
        cred.service.should eq("MyService")
        cred.username.should eq("myuser")
        cred.password.should eq("mypass")
        cred.created_at.should be_a(Time)
        cred.modified_at.should be_a(Time)
        cred.metadata.should be_empty
        cred.encrypted?.should be_false
      end

      it "creates credential without password" do
        cred = Credential.new("MyService", "myuser")
        cred.service.should eq("MyService")
        cred.username.should eq("myuser")
        cred.password.should be_nil
      end

      it "encrypts password when encryption key provided" do
        key = Encryption.generate_key
        cred = Credential.new("MyService", "myuser", "mypass", key)

        cred.encrypted?.should be_true
        cred.password.should_not eq("mypass")
        cred.password.should_not be_nil
      end
    end

    describe "#password=" do
      it "updates password and modified timestamp" do
        cred = Credential.new("MyService", "myuser", "oldpass")
        original_time = cred.modified_at

        sleep 10.milliseconds
        cred.password = "newpass"

        cred.password.should eq("newpass")
        cred.modified_at.should be > original_time
      end

      it "encrypts new password if encryption key was provided" do
        key = Encryption.generate_key
        cred = Credential.new("MyService", "myuser", "oldpass", key)

        cred.password = "newpass"
        cred.encrypted?.should be_true
        cred.password.should_not eq("newpass")
      end
    end

    describe "#add_metadata" do
      it "adds metadata key-value pair" do
        cred = Credential.new("MyService", "myuser")
        cred.add_metadata("environment", "production")

        cred.metadata["environment"].should eq("production")
      end

      it "updates modified timestamp" do
        cred = Credential.new("MyService", "myuser")
        original_time = cred.modified_at

        sleep 10.milliseconds
        cred.add_metadata("key", "value")

        cred.modified_at.should be > original_time
      end

      it "overwrites existing metadata" do
        cred = Credential.new("MyService", "myuser")
        cred.add_metadata("env", "dev")
        cred.add_metadata("env", "prod")

        cred.metadata["env"].should eq("prod")
      end
    end

    describe "#remove_metadata" do
      it "removes metadata key" do
        cred = Credential.new("MyService", "myuser")
        cred.add_metadata("temp", "value")
        cred.remove_metadata("temp")

        cred.metadata.has_key?("temp").should be_false
      end

      it "updates modified timestamp" do
        cred = Credential.new("MyService", "myuser")
        cred.add_metadata("key", "value")
        original_time = cred.modified_at

        sleep 10.milliseconds
        cred.remove_metadata("key")

        cred.modified_at.should be > original_time
      end
    end

    describe "#decrypt_password" do
      it "returns plain password if not encrypted" do
        cred = Credential.new("MyService", "myuser", "plainpass")
        cred.decrypt_password.should eq("plainpass")
      end

      it "decrypts encrypted password" do
        key = Encryption.generate_key
        cred = Credential.new("MyService", "myuser", "secretpass", key)

        decrypted = cred.decrypt_password
        decrypted.should eq("secretpass")
      end

      it "returns nil if password is nil" do
        cred = Credential.new("MyService", "myuser")
        cred.decrypt_password.should be_nil
      end
    end

    describe "#to_json" do
      it "serializes credential to JSON" do
        cred = Credential.new("MyService", "myuser", "mypass")
        cred.add_metadata("env", "test")

        json = cred.to_json
        json.should contain("MyService")
        json.should contain("myuser")
        json.should contain("env")
      end

      it "excludes encryption_key from JSON" do
        key = Encryption.generate_key
        cred = Credential.new("MyService", "myuser", "mypass", key)

        json = cred.to_json
        json.should_not contain(key)
      end
    end

    describe ".from_json" do
      it "deserializes credential from JSON" do
        original = Credential.new("MyService", "myuser", "mypass")
        original.add_metadata("key", "value")

        json = original.to_json
        restored = Credential.from_json(json)

        restored.service.should eq("MyService")
        restored.username.should eq("myuser")
        restored.password.should eq("mypass")
        restored.metadata["key"].should eq("value")
      end
    end

    describe "#to_s" do
      it "returns string representation without password" do
        cred = Credential.new("MyService", "myuser", "secretpass")

        str = cred.to_s
        str.should contain("MyService")
        str.should contain("myuser")
        str.should_not contain("secretpass")
      end
    end
  end

  describe AnonymousCredential do
    it "holds a password with no username" do
      ac = AnonymousCredential.new("s3cret")
      ac.password.should eq("s3cret")
    end

    it "raises when accessing username" do
      ac = AnonymousCredential.new("pw")
      expect_raises(KeyringError) { ac.username }
    end

    it "converts to hash" do
      ac = AnonymousCredential.new("pw")
      h = ac.to_h
      h["password"].should eq("pw")
      h.has_key?("username").should be_false
    end
  end

  describe EnvironCredential do
    it "reads username and password from environment" do
      with_env("TEST_USER_ENV", "alice") do
        with_env("TEST_PASS_ENV", "hunter2") do
          ec = EnvironCredential.new("TEST_USER_ENV", "TEST_PASS_ENV")
          ec.username.should eq("alice")
          ec.password.should eq("hunter2")
        end
      end
    end

    it "raises when env var is missing" do
      ec = EnvironCredential.new("MISSING_USER", "MISSING_PASS")
      expect_raises(KeyringError) { ec.username }
    end

    it "supports equality comparison" do
      a = EnvironCredential.new("A", "B")
      b = EnvironCredential.new("A", "B")
      c = EnvironCredential.new("A", "C")
      a.should eq(b)
      b.should_not eq(c)
    end
  end
end
