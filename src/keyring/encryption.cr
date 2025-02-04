require "sodium"
require "base64"

module Keyring
  class Encryption
    # Encryption constants
    KEY_LENGTH   = Sodium::SecretBox::KEYBYTES
    NONCE_LENGTH = Sodium::SecretBox::NONCEBYTES

    # Generate a secure random encryption key
    def self.generate_key : String
      key = Sodium::SecretBox.random_key
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

        # Generate a random nonce
        nonce = Sodium::SecretBox.random_nonce

        # Encrypt the data
        encrypted_data = Sodium::SecretBox.seal(data.to_slice, nonce, raw_key)

        # Combine nonce and encrypted data, then base64 encode
        Base64.strict_encode(nonce + encrypted_data)
      rescue ex : ArgumentError | Sodium::CryptoError
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

        # Extract nonce and encrypted data
        nonce = raw[0, NONCE_LENGTH]
        data = raw[NONCE_LENGTH, raw.size - NONCE_LENGTH]

        # Decode the base64 key
        raw_key = Base64.decode(key)

        # Ensure key is correct length
        raise EncryptionError.new("Invalid key length") if raw_key.size != KEY_LENGTH

        # Decrypt the data
        decrypted_data = Sodium::SecretBox.open(data, nonce, raw_key)

        # Convert decrypted data to string
        String.new(decrypted_data)
      rescue ex : Sodium::CryptoError | Base64::Error
        raise EncryptionError.new("Decryption failed: #{ex.message}")
      end
    end

    # Password hashing for credential verification
    def self.hash_password(password : String) : String
      # Use Argon2 for password hashing
      salt = Sodium.random_bytes(Sodium::PasswordHash::SALTBYTES)
      hash = Sodium::PasswordHash.hash(
        password,
        salt,
        Sodium::PasswordHash::OPSLIMIT_INTERACTIVE,
        Sodium::PasswordHash::MEMLIMIT_INTERACTIVE
      )
      Base64.strict_encode(hash)
    end

    # Verify a password against a hash
    def self.verify_password(password : String, hash : String) : Bool
      # Decode the base64 stored hash
      stored_hash = Base64.decode(hash)

      # Verify the password
      Sodium::PasswordHash.verify(stored_hash, password)
    rescue
      false
    end

    # Generate a secure random token
    def self.generate_token(length : Int32 = 32) : String
      Sodium.random_bytes(length).hexstring
    end

    # Generate a secure random salt
    def self.generate_salt : String
      Base64.strict_encode(Sodium.random_bytes(Sodium::PasswordHash::SALTBYTES))
    end
  end
end
