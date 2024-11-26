require "win32cr/advapi32"
require "./backend"
require "./errors"

module Keyring
  class WindowsBackend < Backend
    def self.available? : Bool
      {% if flag?(:windows) %}
        true
      {% else %}
        false
      {% end %}
    end

    def get_password(service : String, username : String) : String?
      {% if flag?(:windows) %}
        target = "#{service}:#{username}"
        begin
          cred = Win32CR::Advapi32.credential_read(target, Win32CR::Advapi32::CRED_TYPE_GENERIC)
          return String.new(cred.credential_blob.to_unsafe.as(UInt8*), cred.credential_blob_size)
        rescue Win32CR::Win32Error
          return nil
        end
      {% else %}
        raise NoBackendError.new("Windows backend not available")
      {% end %}
    end

    def set_password(service : String, username : String, password : String)
      {% if flag?(:windows) %}
        target = "#{service}:#{username}"
        begin
          Win32CR::Advapi32.credential_write(
            target,
            Win32CR::Advapi32::CRED_TYPE_GENERIC,
            password.to_slice,
            username
          )
        rescue ex : Win32CR::Win32Error
          raise PasswordSetError.new("Failed to store password: #{ex.message}")
        end
      {% else %}
        raise NoBackendError.new("Windows backend not available")
      {% end %}
    end

    def delete_password(service : String, username : String)
      {% if flag?(:windows) %}
        target = "#{service}:#{username}"
        begin
          Win32CR::Advapi32.credential_delete(target, Win32CR::Advapi32::CRED_TYPE_GENERIC)
        rescue ex : Win32CR::Win32Error
          raise PasswordDeleteError.new("Failed to delete password: #{ex.message}")
        end
      {% else %}
        raise NoBackendError.new("Windows backend not available")
      {% end %}
    end

    def get_credential(service : String, username : String) : Credential?
      if password = get_password(service, username)
        Credential.new(service, username, password)
      end
    end

    def list_credentials : Array(Credential)
      {% if flag?(:windows) %}
        creds = [] of Credential
        begin
          Win32CR::Advapi32.credential_enumerate.each do |cred|
            if cred.type == Win32CR::Advapi32::CRED_TYPE_GENERIC
              target = String.new(cred.target_name)
              if target =~ /^(.+):(.+)$/
                service = $1
                username = $2
                password = String.new(cred.credential_blob.to_unsafe.as(UInt8*), cred.credential_blob_size)
                creds << Credential.new(service, username, password)
              end
            end
          end
        rescue ex : Win32CR::Win32Error
          Log.warn { "Failed to enumerate credentials: #{ex.message}" }
        end
        creds
      {% else %}
        [] of Credential
      {% end %}
    end
  end
end
