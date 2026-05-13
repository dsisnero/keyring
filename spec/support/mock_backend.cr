require "../../src/keyring/backend"
require "../../src/keyring/credential"
require "../../src/keyring/errors"

module Keyring
  # Mock backend for testing - stores credentials in memory
  class MockBackend < Backend
    getter storage : Hash(String, Credential)

    def initialize
      @storage = {} of String => Credential
    end

    def self.available? : Bool
      true
    end

    def get_password(service : String, username : String) : String?
      key = make_key(service, username)
      @storage[key]?.try(&.password)
    end

    def set_password(service : String, username : String, password : String)
      key = make_key(service, username)
      if existing = @storage[key]?
        existing.password = password
      else
        @storage[key] = Credential.new(service, username, password)
      end
    end

    def delete_password(service : String, username : String)
      key = make_key(service, username)
      unless @storage.has_key?(key)
        raise PasswordDeleteError.new("Password not found: #{service}:#{username}")
      end
      @storage.delete(key)
    end

    def get_credential(service : String, username : String) : Credential?
      key = make_key(service, username)
      @storage[key]?
    end

    def list_credentials : Array(Credential)
      @storage.values
    end

    # Helper to clear all stored credentials
    def clear
      @storage.clear
    end

    # Helper to get credential count
    def size
      @storage.size
    end

    private def make_key(service : String, username : String) : String
      "#{service}:#{username}"
    end
  end
end
