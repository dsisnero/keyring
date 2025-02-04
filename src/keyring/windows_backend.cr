# require "win32/security"
require "win32cr"
require "win32cr/security/credentials"
require "./backend"
require "./errors"

module Keyring
  module Windows::Credential
    # alias Handle = LibC::CREDENTIALW*

    protected def initialize(credentialw : Handle)
      @username = credentialw.value.username
      @targetname = credentialw.value.target_name
    end
  end

  class WindowsBackend < Backend
    # Constants for credential filtering
    private SUPPORTED_CREDENTIAL_TYPES = [
      LibWin32::CRED_TYPE::CRED_TYPE_GENERIC,
    ]

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
        win_target = target.to_utf16
        credential_ptr = Pointer(LibWin32::CREDENTIALW).null
        ret = LibWin32.CredReadW(win_target, CRED_TYPE_GENERIC, 0, pointerof(credential_ptr))
        if ret != 0
          begin
            credential = credential_ptr.value
            # safely extract credential blob
            return String.new(credential.credential_blob.as(UInt8*), credential.credential_blob_size)
          ensure
            LibWin32.CredFree(credential_ptr)
          end
        end
      {% else %}
        raise NoBackendError.new("Windows backend not available")
      {% end %}
      nil
    end

    # def set_password(service : String, username : String, password : String)
    #   {% if flag?(:windows) %}
    #     target = "#{service}:#{username}"
    #     credential = LibWin32::CREDENTIALW.new
    #     credential.type = CRED_TYPE_GENERIC
    #     credential.target_name = target.to_utf16
    #     credential.user_name = username.to_utf16
    #     credential.credential_blob = password.to_slice.to_unsafe
    #     credential.credential_blob_size = password.bytesize
    #     credential.persist = LibWin32::CRED_PERSIST::CRED_PERSIST_LOCAL_MACHINE

    #     if LibWin32.CredWriteW(pointerof(credential), 0) == 0
    #       raise PasswordSetError.new("Failed to store password")
    #     end
    #   {% else %}
    #     raise NoBackendError.new("Windows backend not available")
    #   {% end %}
    # end

    # More robust password setting
    def set_password(service : String, username : String, password : String)
      target = "#{service}:#{username}"

      # Prepare credential structure
      credential = LibWin32::CREDENTIALW.new
      credential.type = CRED_TYPE_GENERIC
      credential.target_name = target.to_utf16
      credential.user_name = username.to_utf16

      # Convert password to slice
      password_slice = password.to_slice

      credential.credential_blob = password_slice.to_unsafe
      credential.credential_blob_size = password_slice.size.to_u32

      # Set persistence level
      credential.persist = LibWin32::CRED_PERSIST::CRED_PERSIST_LOCAL_MACHINE

      # Write credential
      if LibWin32.CredWriteW(pointerof(credential), 0_u32) == 0
        # Get Windows error code
        error_code = LibC.GetLastError
        raise PasswordSetError.new(
          "Failed to store password. Error code: #{error_code}"
        )
      end
    rescue ex
      Log.error { "Password set failed: #{ex.message}" }
      raise
    end

    # def delete_password(service : String, username : String)
    #   {% if flag?(:windows) %}
    #     target = "#{service}:#{username}"
    #     if LibWin32.CredDeleteW(target.to_utf16, CRED_TYPE_GENERIC, 0) == 0
    #       raise PasswordDeleteError.new("Failed to delete password")
    #     end
    #   {% else %}
    #     raise NoBackendError.new("Windows backend not available")
    #   {% end %}
    # end

    # Improved delete_password with better error handling
    def delete_password(service : String, username : String)
      target = "#{service}:#{username}"

      if LibWin32.CredDeleteW(
           target.to_utf16,
           CRED_TYPE_GENERIC,
           0_u32
         ) == 0
        error_code = LibC.GetLastError
        raise PasswordDeleteError.new(
          "Failed to delete password. Error code: #{error_code}"
        )
      end
    rescue ex
      Log.error { "Password deletion failed: #{ex.message}" }
      raise
    end

    def get_credential(service : String, username : String) : Credential?
      if password = get_password(service, username)
        Credential.new(service, username, password)
      end
    end

    # Main method to list credentials
    def list_credentials : Array(Credential)
      enumerate_windows_credentials
        .compact
    end

    # Core method to enumerate credentials
    private def enumerate_windows_credentials : Array(Credential?)
      credentials = [] of Credential?

      begin
        count = uninitialized UInt32
        credentials_ptr = uninitialized LibWin32::CREDENTIALW**

        if enumerate_credentials(pointerof(count), pointerof(credentials_ptr))
          process_credential_list(credentials_ptr, count, credentials)
        end
      rescue ex
        Log.error { "Failed to enumerate credentials: #{ex.message}" }
      end

      credentials
    end

    # Enumerate credentials using Windows API
    private def enumerate_credentials(
      count_ptr : UInt32*,
      credentials_ptr_ptr : LibWin32::CREDENTIALW***,
    ) : Bool
      LibWin32.CredEnumerateW(
        nil,   # Enumerate all credentials
        0_u32, # Flags (0 means default)
        count_ptr,
        credentials_ptr_ptr
      ) != 0
    end

    # Process the list of credentials
    private def process_credential_list(
      credentials_ptr : LibWin32::CREDENTIALW**,
      count : UInt32,
      results : Array(Credential?),
    )
      count.times do |i|
        cred = credentials_ptr.value[i]

        # Skip unsupported credential types
        next unless valid_credential_type?(cred)

        # Try to parse and add credential
        results << parse_credential(cred)
      end
    ensure
      # Always free the credentials
      LibWin32.CredFree(credentials_ptr) unless credentials_ptr.null?
    end

    # Validate credential type
    private def valid_credential_type?(cred : LibWin32::CREDENTIALW) : Bool
      SUPPORTED_CREDENTIAL_TYPES.includes?(cred.type)
    end

    # Parse a single credential
    private def parse_credential(cred : LibWin32::CREDENTIALW) : Credential?
      # Parse target name
      target = parse_target_name(cred)
      return nil unless target

      begin
        service, username = target
        password = extract_password(cred)

        credential = build_credential(
          service: service,
          username: username,
          password: password,
          cred: cred
        )

        credential
      rescue ex
        Log.warn { "Could not process credential: #{ex.message}" }
        nil
      end
    end

    # Extract target name and split into service and username
    private def parse_target_name(cred : LibWin32::CREDENTIALW) : {String, String}?
      target = String.new(cred.target_name)

      # Match the expected format of "service:username"
      if target =~ /^(.+):(.+)$/
        {$1, $2}
      else
        Log.debug { "Skipping credential with invalid target format: #{target}" }
        nil
      end
    end

    # Safely extract password from credential
    private def extract_password(cred : LibWin32::CREDENTIALW) : String
      String.new(
        cred.credential_blob.to_unsafe.as(UInt8*),
        cred.credential_blob_size
      )
    end

    # Build a full Credential object with additional metadata
    private def build_credential(
      service : String,
      username : String,
      password : String,
      cred : LibWin32::CREDENTIALW,
    ) : Credential
      credential = Credential.new(
        service: service,
        username: username,
        password: password
      )

      # Add Windows-specific metadata
      add_windows_metadata(credential, cred)

      credential
    end

    # Add Windows-specific metadata to credential
    private def add_windows_metadata(
      credential : Credential,
      win_cred : LibWin32::CREDENTIALW,
    )
      metadata_mappings = {
        "persist_type"    => win_cred.persist.to_s,
        "credential_type" => win_cred.type.to_s,
        "last_written"    => format_file_time(win_cred.last_written),
      }

      metadata_mappings.each do |key, value|
        credential.add_metadata(key, value)
      end
    end

    # Convert Windows FILETIME to a readable format
    private def format_file_time(file_time : LibWin32::FILETIME) : String
      # Convert FILETIME to Crystal Time
      # FILETIME is 100-nanosecond intervals since January 1, 1601
      # Epoch for Time is January 1, 1970
      windows_epoch = Time.utc(1601, 1, 1)

      # Convert to 64-bit integer
      timestamp = (file_time.high_date_time.to_u64 << 32) | file_time.low_date_time.to_u64

      # Convert to seconds
      seconds = timestamp / 10_000_000

      (windows_epoch + Time::Span.new(seconds: seconds)).to_s
    end
  end
end
