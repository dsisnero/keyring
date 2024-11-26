require "crypto/bcrypt"
 require "crypto/subtle"
 require "base64"
 require "openssl"

 module Keyring
   class EncryptionError < Error; end

   class Encryption
     CIPHER = "AES-256-CBC"

     def self.generate_key : String
       Base64.strict_encode(Random::Secure.random_bytes(32))
     end

     def self.encrypt(data : String, key : String) : String
       begin
         cipher = OpenSSL::Cipher.new(CIPHER)
         cipher.encrypt

         # Generate random IV
         iv = Random::Secure.random_bytes(16)
         cipher.iv = iv

         # Decode key from Base64
         raw_key = Base64.decode(key)
         cipher.key = raw_key

         # Encrypt the data
         encrypted = cipher.update(data)
         encrypted += cipher.final

         # Combine IV and encrypted data and encode
         Base64.strict_encode(iv + encrypted)
       rescue e
         raise EncryptionError.new("Failed to encrypt: #{e.message}")
       end
     end

     def self.decrypt(encrypted_data : String, key : String) : String
       begin
         # Decode the combined data
         combined = Base64.decode(encrypted_data)

         # Split IV and encrypted data
         iv = combined[0, 16]
         combined = Base64.decode(encrypted_data)

         # Split IV and encrypted data
         iv = combined[0, 16]
     def self.decrypt(encrypted_data : String, key : String) : String
       raw = Base64.decode(encrypted_data)

       # Extract salt, IV, and encrypted data
       salt = raw[0, 16]
       iv = raw[16, 16]
       data = raw[32..-1]

       cipher = OpenSSL::Cipher.new(CIPHER)
       cipher.decrypt

       key_bytes = generate_key(key, Base64.encode(salt))
       cipher.key = key_bytes
       cipher.iv = iv

       decrypted = cipher.update(data)
       decrypted += cipher.final

       String.new(decrypted)
     rescue ex : OpenSSL::Error | OpenSSL::Cipher::Error | Base64::Error
       raise EncryptionError.new("Decryption failed: #{ex.message}")
     end

     def self.hash_password(password : String) : String
       Crypto::Bcrypt::Password.create(password, cost: 12).to_s
     end

     def self.verify_password(password : String, hash : String) : Bool
       bcrypt = Crypto::Bcrypt::Password.new(hash)
       Crypto::Subtle.constant_time_compare(bcrypt.to_s, hash)
     rescue
       false
     end
   end
 end
