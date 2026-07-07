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

  describe SecretBoxCrypter do
    it "encrypts and decrypts roundtrip" do
      key = Encryption.generate_key
      crypter = SecretBoxCrypter.new(key)
      original = "secret-data-123"
      encrypted = crypter.encrypt(original)
      encrypted.should_not eq(original)
      crypter.decrypt(encrypted).should eq(original)
    end

    it "raises EncryptionError for wrong key" do
      key1 = Encryption.generate_key
      key2 = Encryption.generate_key
      crypter1 = SecretBoxCrypter.new(key1)
      crypter2 = SecretBoxCrypter.new(key2)
      encrypted = crypter1.encrypt("data")
      expect_raises(EncryptionError) { crypter2.decrypt(encrypted) }
    end

    it "raises EncryptionError for empty data" do
      key = Encryption.generate_key
      crypter = SecretBoxCrypter.new(key)
      expect_raises(EncryptionError) { crypter.encrypt("") }
      expect_raises(EncryptionError) { crypter.decrypt("") }
    end
  end

  describe CryptoBoxCrypter do
    it "encrypts and decrypts roundtrip" do
      kp = Keypair.generate_encryption
      crypter = CryptoBoxCrypter.new(kp.public_key, kp.secret_key)
      original = "asymmetric-data-456"
      encrypted = crypter.encrypt(original)
      encrypted.should_not eq(original)
      crypter.decrypt(encrypted).should eq(original)
    end

    it "raises for wrong key" do
      kp1 = Keypair.generate_encryption
      kp2 = Keypair.generate_encryption
      crypter1 = CryptoBoxCrypter.new(kp1.public_key, kp1.secret_key)
      crypter2 = CryptoBoxCrypter.new(kp2.public_key, kp2.secret_key)
      encrypted = crypter1.encrypt("data")
      expect_raises(EncryptionError) { crypter2.decrypt(encrypted) }
    end

    it "raises for invalid key length" do
      bad_key = Base64.strict_encode("x".to_slice)
      expect_raises(EncryptionError) do
        CryptoBoxCrypter.new(bad_key, bad_key)
      end
    end
  end

  describe Keypair do
    it "generates encryption keypair" do
      kp = Keypair.generate_encryption
      Base64.decode(kp.public_key).size.should eq(Sodium::CryptoBox::PublicKey::KEY_SIZE)
      Base64.decode(kp.secret_key).size.should eq(Sodium::CryptoBox::SecretKey::KEY_SIZE)
    end

    it "generates signing keypair" do
      kp = Keypair.generate_signing
      Base64.decode(kp.public_key).size.should eq(Sodium::Sign::PublicKey::KEY_SIZE)
      Base64.decode(kp.secret_key).size.should eq(Sodium::Sign::SecretKey::KEY_SIZE)
    end

    it "signs and verifies data" do
      kp = Keypair.generate_signing
      data = "important data to sign"
      sig = kp.sign(data)
      sig.should_not be_empty
      kp.verify(data, sig).should be_true
    end

    it "rejects invalid signature" do
      kp = Keypair.generate_signing
      data = "original data"
      sig = kp.sign(data)
      kp.verify("tampered data", sig).should be_false
    end

    it "generates unique keypairs" do
      kp1 = Keypair.generate_encryption
      kp2 = Keypair.generate_encryption
      kp1.public_key.should_not eq(kp2.public_key)
      kp1.secret_key.should_not eq(kp2.secret_key)
    end
  end

  describe Encryption do
    describe ".build_crypter" do
      it "returns NullCrypter when encryption disabled" do
        config = Config.new
        config.encrypt_passwords = false
        crypter = Encryption.build_crypter(config)
        crypter.should be_a(NullCrypter)
      end

      it "returns SecretBoxCrypter for default encryption type" do
        config = Config.new
        config.encrypt_passwords = true
        config.encryption_key = Encryption.generate_key
        crypter = Encryption.build_crypter(config)
        crypter.should be_a(SecretBoxCrypter)
      end

      it "returns CryptoBoxCrypter for asymmetric encryption type" do
        kp = Keypair.generate_encryption
        config = Config.new
        config.encrypt_passwords = true
        config.encryption_type = "asymmetric"
        config.encryption_public_key = kp.public_key
        config.encryption_secret_key = kp.secret_key
        crypter = Encryption.build_crypter(config)
        crypter.should be_a(CryptoBoxCrypter)
      end

      it "raises ConfigError when asymmetric missing keys" do
        config = Config.new
        config.encrypt_passwords = true
        config.encryption_type = "asymmetric"
        expect_raises(ConfigError) { Encryption.build_crypter(config) }
      end

      it "raises ConfigError when symmetric missing key" do
        config = Config.new
        config.encrypt_passwords = true
        expect_raises(ConfigError) { Encryption.build_crypter(config) }
      end
    end
  end
end
