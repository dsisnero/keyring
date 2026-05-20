require "sodium"
require "base64"

module Keyring
  abstract class Crypter
    abstract def encrypt(value : String) : String
    abstract def decrypt(value : String) : String
  end

  # No-op crypter (passes data through unchanged)
  class NullCrypter < Crypter
    def encrypt(value : String) : String
      value
    end

    def decrypt(value : String) : String
      value
    end
  end

  # Symmetric authenticated encryption: XSalsa20-Poly1305 via Sodium::SecretBox
  class SecretBoxCrypter < Crypter
    KEY_LENGTH = Sodium::SecretBox::KEY_SIZE

    getter key : Bytes

    def initialize(key : String)
      raw = Base64.decode(key)
      raise EncryptionError.new("Invalid key length") if raw.size != KEY_LENGTH
      @key = raw
    end

    def encrypt(value : String) : String
      raise EncryptionError.new("Data cannot be empty") if value.empty?
      box = Sodium::SecretBox.copy_from(@key)
      encrypted_bytes, nonce = box.encrypt(value.to_slice)
      combined = nonce.to_slice + encrypted_bytes
      Base64.strict_encode(combined)
    rescue ex : Sodium::Error | Base64::Error
      raise EncryptionError.new("Encryption failed: #{ex.message}")
    end

    def decrypt(value : String) : String
      raise EncryptionError.new("Encrypted data cannot be empty") if value.empty?
      raw = Base64.decode(value)
      min_size = Sodium::SecretBox::NONCE_SIZE + Sodium::SecretBox::MAC_SIZE
      raise EncryptionError.new("Decryption failed: data too short") if raw.size < min_size
      nonce_bytes = raw[0, Sodium::SecretBox::NONCE_SIZE]
      data = raw[Sodium::SecretBox::NONCE_SIZE, raw.size - Sodium::SecretBox::NONCE_SIZE]
      box = Sodium::SecretBox.copy_from(@key)
      nonce = Sodium::Nonce.new(nonce_bytes)
      String.new(box.decrypt(data, nonce: nonce))
    rescue ex : Sodium::Error | Base64::Error | IndexError
      raise EncryptionError.new("Decryption failed: #{ex.message}")
    end
  end

  # Asymmetric authenticated encryption: Curve25519 + XSalsa20-Poly1305 via Sodium::CryptoBox
  class CryptoBoxCrypter < Crypter
    getter public_key : Bytes
    getter secret_key : Bytes

    def initialize(public_key : String, secret_key : String)
      @public_key = Base64.decode(public_key)
      @secret_key = Base64.decode(secret_key)
      raise EncryptionError.new("Invalid public key length") if @public_key.size != Sodium::CryptoBox::PUBLIC_KEY_SIZE
      raise EncryptionError.new("Invalid secret key length") if @secret_key.size != Sodium::CryptoBox::SECRET_KEY_SIZE
    end

    def encrypt(value : String) : String
      raise EncryptionError.new("Data cannot be empty") if value.empty?
      box = Sodium::CryptoBox.copy_from(@public_key, @secret_key)
      encrypted_bytes, nonce = box.encrypt(value.to_slice)
      combined = nonce.to_slice + encrypted_bytes
      Base64.strict_encode(combined)
    rescue ex : Sodium::Error | Base64::Error
      raise EncryptionError.new("Encryption failed: #{ex.message}")
    end

    def decrypt(value : String) : String
      raise EncryptionError.new("Encrypted data cannot be empty") if value.empty?
      raw = Base64.decode(value)
      min_size = Sodium::CryptoBox::NONCE_SIZE + Sodium::CryptoBox::MAC_SIZE
      raise EncryptionError.new("Decryption failed: data too short") if raw.size < min_size
      nonce_bytes = raw[0, Sodium::CryptoBox::NONCE_SIZE]
      data = raw[Sodium::CryptoBox::NONCE_SIZE, raw.size - Sodium::CryptoBox::NONCE_SIZE]
      box = Sodium::CryptoBox.copy_from(@public_key, @secret_key)
      nonce = Sodium::Nonce.new(nonce_bytes)
      String.new(box.decrypt(data, nonce: nonce))
    rescue ex : Sodium::Error | Base64::Error | IndexError
      raise EncryptionError.new("Decryption failed: #{ex.message}")
    end
  end

  # Keypair: encryption keypair (Curve25519) or signing keypair (Ed25519)
  class Keypair
    getter public_key : String
    getter secret_key : String

    def initialize(@public_key : String, @secret_key : String)
    end

    # Generate a new encryption keypair (Curve25519)
    def self.generate_encryption : Keypair
      pk = Bytes.new(Sodium::CryptoBox::PUBLIC_KEY_SIZE)
      sk = Bytes.new(Sodium::CryptoBox::SECRET_KEY_SIZE)
      Sodium::CryptoBox.keypair(pk, sk)
      Keypair.new(Base64.strict_encode(pk), Base64.strict_encode(sk))
    end

    # Generate a new signing keypair (Ed25519)
    def self.generate_signing : Keypair
      pk = Bytes.new(Sodium::Sign::PUBLIC_KEY_SIZE)
      sk = Bytes.new(Sodium::Sign::SECRET_KEY_SIZE)
      Sodium::Sign.keypair(pk, sk)
      Keypair.new(Base64.strict_encode(pk), Base64.strict_encode(sk))
    end

    # Sign data with the secret key, returns base64 signature
    def sign(data : String) : String
      raw_sk = Base64.decode(@secret_key)
      sig = Bytes.new(Sodium::Sign::SIGNATURE_SIZE)
      Sodium::Sign.sign_detached(sig, data.to_slice, raw_sk)
      Base64.strict_encode(sig)
    end

    # Verify a signature against data using the public key
    def verify(data : String, signature : String) : Bool
      raw_pk = Base64.decode(@public_key)
      raw_sig = Base64.decode(signature)
      Sodium::Sign.verify_detached(raw_sig, data.to_slice, raw_pk)
      true
    rescue Sodium::Error
      false
    end
  end

  class Encryption
    KEY_LENGTH = Sodium::SecretBox::KEY_SIZE

    # Generate a symmetric key for SecretBox encryption
    def self.generate_key : String
      key = Random::Secure.random_bytes(Sodium::SecretBox::KEY_SIZE)
      Base64.strict_encode(key)
    end

    # Generate a keypair for asymmetric CryptoBox encryption
    def self.generate_keypair : Keypair
      Keypair.generate_encryption
    end

    # Generate a signing keypair (Ed25519)
    def self.generate_signing_keypair : Keypair
      Keypair.generate_signing
    end

    # Build a crypter from config
    def self.build_crypter(config : Config) : Crypter
      return NullCrypter.new unless config.encrypt_passwords?

      case config.encryption_type
      when "asymmetric", "cryptobox"
        pub = config.encryption_public_key
        sec = config.encryption_secret_key || config.encryption_key
        raise ConfigError.new("Asymmetric encryption requires both public_key and secret_key") unless pub && sec
        CryptoBoxCrypter.new(pub, sec)
      else
        key = config.encryption_key
        raise ConfigError.new("Encryption key not configured") unless key
        SecretBoxCrypter.new(key)
      end
    end

    # Encrypt a string using the legacy API (symmetric only)
    def self.encrypt(data : String, key : String) : String
      raise EncryptionError.new("Key cannot be empty") if key.empty?
      SecretBoxCrypter.new(key).encrypt(data)
    end

    # Decrypt a string using the legacy API (symmetric only)
    def self.decrypt(encrypted_data : String, key : String) : String
      raise EncryptionError.new("Key cannot be empty") if key.empty?
      SecretBoxCrypter.new(key).decrypt(encrypted_data)
    end

    # Password hashing for credential verification
    def self.hash_password(password : String) : String
      pwhash = Sodium::Password::Hash.new
      pwhash.mem = Sodium::Password::MEMLIMIT_INTERACTIVE
      pwhash.ops = Sodium::Password::OPSLIMIT_INTERACTIVE
      String.new(pwhash.create(password))
    end

    # Verify a password against a hash
    def self.verify_password(password : String, hash_str : String) : Bool
      pwhash = Sodium::Password::Hash.new
      pwhash.verify(hash_str, password)
      true
    rescue Sodium::Password::Error::Verify
      false
    end

    # Generate a secure random token
    def self.generate_token(length : Int32 = 32) : String
      Random::Secure.random_bytes(length).hexstring
    end

    # Generate a secure random salt
    def self.generate_salt : String
      Base64.strict_encode(Random::Secure.random_bytes(32))
    end
  end
end
