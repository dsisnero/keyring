require "./backend"
require "./credential"

module Keyring
  # Backend that chains multiple other backends, trying each in sequence.
  # For get_password/get_credential, returns the first non-nil result.
  # For set_password/delete_password, tries each backend ignoring errors.
  # For list_credentials, merges results from all backends.
  #
  # Ported from: python-keyring keyring/backends/chainer.py (v25.7.0)
  class ChainerBackend < Backend
    Backend.register(self)
    getter backends : Array(Backend)

    def self.available? : Bool
      false
    end

    def initialize(*backends)
      @backends = backends.to_a.map { |backend| backend.as(Backend) }
    end

    def get_password(service : String, username : String) : String?
      @backends.each do |backend|
        begin
          password = backend.get_password(service, username)
          return password unless password.nil?
        rescue ex
          # Skip backends that fail on get
        end
      end
      nil
    end

    def set_password(service : String, username : String, password : String)
      last_error : Exception? = nil
      @backends.each do |backend|
        begin
          backend.set_password(service, username, password)
          return
        rescue ex
          last_error = ex
        end
      end
      raise last_error || PasswordSetError.new("All backends failed to set password")
    end

    def delete_password(service : String, username : String)
      last_error : Exception? = nil
      @backends.each do |backend|
        begin
          backend.delete_password(service, username)
          return
        rescue ex
          last_error = ex
        end
      end
      raise last_error || PasswordDeleteError.new("All backends failed to delete password")
    end

    def get_credential(service : String, username : String) : Credential?
      @backends.each do |backend|
        begin
          credential = backend.get_credential(service, username)
          return credential unless credential.nil?
        rescue ex
          # Skip backends that fail on get_credential
        end
      end
      nil
    end

    def list_credentials : Array(Credential)
      all = [] of Credential
      @backends.each do |backend|
        begin
          all.concat(backend.list_credentials)
        rescue ex
          # Skip backends that fail on list
        end
      end
      all
    end
  end
end
