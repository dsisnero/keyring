require "sodium"
require "base64"

module Keyring
  abstract class Crypter
    abstract def encrypt(value : String) : String
    abstract def decrypt(value : String) : String
  end

  class NullCrypter < Crypter
    def encrypt(value : String) : String
      value
    end

    def decrypt(value : String) : String
      value
    end
  end

  class Encryption
    # Encryption constants
    KEY_LENGTH   = Sodium::SecretBox::KEY_SIZE
    NONCE_LENGTH = Sodium::SecretBox::NONCE_SIZE

    # Generate a secure random encryption key
    def self.generate_key : String
      key = Random::Secure.random_bytes(KEY_LENGTH)
      Base64.strict_encode(key)
    end

    # Encrypt a string with a given key
    def self.encrypt(data : String, key : String) : String
      # Validate inputs
      raise EncryptionError.new("Data cannot be empty") if data.empty?
      raise EncryptionError.new("Key cannot be empty") if key.empty?

      begin
        # Decode the base64 key
        raw_key = Base64.decode(key)

        # Ensure key is correct length
        raise EncryptionError.new("Invalid key length") if raw_key.size != KEY_LENGTH

        # Create SecretBox with the key
        box = Sodium::SecretBox.copy_from(raw_key)

        # Encrypt the data (returns tuple of encrypted bytes and nonce)
        encrypted_bytes, nonce = box.encrypt(data.to_slice)

        # Combine nonce and encrypted data, then base64 encode
        combined = nonce.to_slice + encrypted_bytes
        Base64.strict_encode(combined)
      rescue ex : ArgumentError | Sodium::Error
        raise EncryptionError.new("Encryption failed: #{ex.message}")
      end
    end

    # Decrypt a string with a given key
    def self.decrypt(encrypted_data : String, key : String) : String
      # Validate inputs
      raise EncryptionError.new("Encrypted data cannot be empty") if encrypted_data.empty?
      raise EncryptionError.new("Key cannot be empty") if key.empty?

      begin
        # Decode the base64 encrypted data
        raw = Base64.decode(encrypted_data)

        # Validate minimum length
        min_size = NONCE_LENGTH + Sodium::SecretBox::MAC_SIZE
        raise EncryptionError.new("Decryption failed: data too short") if raw.size < min_size

        # Extract nonce and encrypted data
        nonce_bytes = raw[0, NONCE_LENGTH]
        data = raw[NONCE_LENGTH, raw.size - NONCE_LENGTH]

        # Decode the base64 key
        raw_key = Base64.decode(key)

        # Ensure key is correct length
        raise EncryptionError.new("Invalid key length") if raw_key.size != KEY_LENGTH

        # Create SecretBox with the key
        box = Sodium::SecretBox.copy_from(raw_key)

        # Create Nonce from bytes
        nonce = Sodium::Nonce.new(nonce_bytes)

        # Decrypt the data
        decrypted_data = box.decrypt(data, nonce: nonce)

        # Convert decrypted data to string
        String.new(decrypted_data)
      rescue ex : Sodium::Error | Base64::Error | IndexError
        raise EncryptionError.new("Decryption failed: #{ex.message}")
      end
    end

    # Password hashing for credential verification
    def self.hash_password(password : String) : String
      # Use Argon2 for password hashing
      pwhash = Sodium::Password::Hash.new
      pwhash.mem = Sodium::Password::MEMLIMIT_INTERACTIVE
      pwhash.ops = Sodium::Password::OPSLIMIT_INTERACTIVE

      hash = pwhash.create(password)
      String.new(hash)
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
      salt = Random::Secure.random_bytes(32)
      Base64.strict_encode(salt)
    end
  end
end
