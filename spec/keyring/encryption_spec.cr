require "../spec_helper"

module Keyring
  describe Encryption do
    describe ".generate_key" do
      it "generates a valid base64 key" do
        key = Encryption.generate_key
        key.should_not be_empty

        # Should be valid base64
        decoded = Base64.decode(key)
        decoded.size.should eq(Encryption::KEY_LENGTH)
      end

      it "generates unique keys" do
        key1 = Encryption.generate_key
        key2 = Encryption.generate_key

        key1.should_not eq(key2)
      end
    end

    describe ".encrypt" do
      it "encrypts data successfully" do
        key = Encryption.generate_key
        data = "secret message"

        encrypted = Encryption.encrypt(data, key)
        encrypted.should_not be_empty
        encrypted.should_not eq(data)
      end

      it "produces different ciphertext for same data (different nonces)" do
        key = Encryption.generate_key
        data = "same message"

        encrypted1 = Encryption.encrypt(data, key)
        encrypted2 = Encryption.encrypt(data, key)

        encrypted1.should_not eq(encrypted2)
      end

      it "raises error for empty data" do
        key = Encryption.generate_key

        expect_raises(EncryptionError, /Data cannot be empty/) do
          Encryption.encrypt("", key)
        end
      end

      it "raises error for empty key" do
        expect_raises(EncryptionError, /Key cannot be empty/) do
          Encryption.encrypt("data", "")
        end
      end

      it "raises error for invalid key length" do
        invalid_key = Base64.strict_encode("tooshort".to_slice)

        expect_raises(EncryptionError, /Invalid key length/) do
          Encryption.encrypt("data", invalid_key)
        end
      end
    end

    describe ".decrypt" do
      it "decrypts encrypted data successfully" do
        key = Encryption.generate_key
        original = "secret message"

        encrypted = Encryption.encrypt(original, key)
        decrypted = Encryption.decrypt(encrypted, key)

        decrypted.should eq(original)
      end

      it "handles unicode characters" do
        key = Encryption.generate_key
        original = "Hello 世界 🔐"

        encrypted = Encryption.encrypt(original, key)
        decrypted = Encryption.decrypt(encrypted, key)

        decrypted.should eq(original)
      end

      it "raises error for empty encrypted data" do
        key = Encryption.generate_key

        expect_raises(EncryptionError, /Encrypted data cannot be empty/) do
          Encryption.decrypt("", key)
        end
      end

      it "raises error for wrong key" do
        key1 = Encryption.generate_key
        key2 = Encryption.generate_key
        original = "secret"

        encrypted = Encryption.encrypt(original, key1)

        expect_raises(EncryptionError, /Decryption failed/) do
          Encryption.decrypt(encrypted, key2)
        end
      end

      it "raises error for corrupted data" do
        key = Encryption.generate_key
        corrupted = Base64.strict_encode("corrupted data".to_slice)

        expect_raises(EncryptionError, /Decryption failed/) do
          Encryption.decrypt(corrupted, key)
        end
      end
    end

    describe ".hash_password" do
      it "hashes password successfully" do
        password = "mypassword123"
        hash = Encryption.hash_password(password)

        hash.should_not be_empty
        hash.should_not eq(password)
      end

      it "produces different hashes for same password (different salts)" do
        password = "samepassword"

        hash1 = Encryption.hash_password(password)
        hash2 = Encryption.hash_password(password)

        hash1.should_not eq(hash2)
      end
    end

    describe ".verify_password" do
      it "verifies correct password" do
        password = "correctpassword"
        hash = Encryption.hash_password(password)

        Encryption.verify_password(password, hash).should be_true
      end

      it "rejects incorrect password" do
        password = "correctpassword"
        hash = Encryption.hash_password(password)

        Encryption.verify_password("wrongpassword", hash).should be_false
      end

      it "returns false for invalid hash" do
        Encryption.verify_password("password", "invalidhash").should be_false
      end
    end

    describe ".generate_token" do
      it "generates token of default length" do
        token = Encryption.generate_token
        token.size.should eq(64) # 32 bytes = 64 hex chars
      end

      it "generates token of custom length" do
        token = Encryption.generate_token(16)
        token.size.should eq(32) # 16 bytes = 32 hex chars
      end

      it "generates unique tokens" do
        token1 = Encryption.generate_token
        token2 = Encryption.generate_token

        token1.should_not eq(token2)
      end
    end

    describe ".generate_salt" do
      it "generates valid salt" do
        salt = Encryption.generate_salt
        salt.should_not be_empty

        decoded = Base64.decode(salt)
        decoded.size.should eq(32)
      end

      it "generates unique salts" do
        salt1 = Encryption.generate_salt
        salt2 = Encryption.generate_salt

        salt1.should_not eq(salt2)
      end
    end
  end
end
