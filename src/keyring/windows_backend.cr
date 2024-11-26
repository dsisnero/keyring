# require "win32/security"
require "win32cr"
require "win32cr/security/credentials"
require "./backend"
require "./errors"

module Keyring
  class WindowsBackend < Backend
    CRED_TYPE_GENERIC = LibWin32::CRED_TYPE::CRED_TYPE_GENERIC
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
        credential = uninitialized LibWin32::CREDENTIALW
        if LibWin32.CredReadW(target.to_utf16, CRED_TYPE_GENERIC, 0, pointerof(credential)) != 0
          begin
            return String.new(credential.credential_blob.to_unsafe.as(UInt8*), credential.credential_blob_size)
          ensure
            LibWin32.CredFree(credential)
          end
        end
      {% else %}
        raise NoBackendError.new("Windows backend not available")
      {% end %}
      nil
    end

    def set_password(service : String, username : String, password : String)
      {% if flag?(:windows) %}
        target = "#{service}:#{username}"
        credential = LibWin32::CREDENTIALW.new
        credential.type = CRED_TYPE_GENERIC
        credential.target_name = target.to_utf16
        credential.user_name = username.to_utf16
        credential.credential_blob = password.to_slice.to_unsafe
        credential.credential_blob_size = password.bytesize
        credential.persist = LibWin32::CRED_PERSIST::CRED_PERSIST_LOCAL_MACHINE

        if LibWin32.CredWriteW(pointerof(credential), 0) == 0
          raise PasswordSetError.new("Failed to store password")
        end
      {% else %}
        raise NoBackendError.new("Windows backend not available")
      {% end %}
    end

    def delete_password(service : String, username : String)
      {% if flag?(:windows) %}
        target = "#{service}:#{username}"
        if LibWin32.CredDeleteW(target.to_utf16, CRED_TYPE_GENERIC, 0) == 0
          raise PasswordDeleteError.new("Failed to delete password")
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
        count = uninitialized UInt32
        credentials = uninitialized LibWin32::CREDENTIALW**

        if LibWin32.CredEnumerateW(nil, 0_u32, pointerof(count), pointerof(credentials)) != 0
          begin
            count.times do |i|
              cred = credentials.value[i]
              if cred.type == CRED_TYPE_GENERIC
                target = String.new(cred.target_name)
                if target =~ /^(.+):(.+)$/
                  service = $1
                  username = $2
                  password = String.new(cred.credential_blob.to_unsafe.as(UInt8*), cred.credential_blob_size)
                  creds << Credential.new(service, username, password)
                end
              end
            end
          ensure
            LibWin32.CredFree(credentials)
          end
        end
        creds
      {% else %}
        [] of Credential
      {% end %}
    end
  end
end
