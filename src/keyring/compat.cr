# Platform compatibility shims for Windows.
# Defines missing POSIX LibC types and constants used by sodium/mmap deps.

{% if flag?(:windows) %}
  lib LibC
    alias UInt64T = UInt64
    alias Int64T = Int64
    alias UInt32T = UInt32
    alias Int32T = Int32
  end

  module LibWin32
    alias CREDENTIALW = Win32cr::Security::Credentials::CREDENTIALW
    alias CREDENTIAL_ATTRIBUTEW = Win32cr::Security::Credentials::CREDENTIAL_ATTRIBUTEW
    alias CRED_TYPE = Win32cr::Security::Credentials::CRED_TYPE
    alias CRED_PERSIST = Win32cr::Security::Credentials::CRED_PERSIST
    alias FILETIME = Win32cr::Foundation::FILETIME

    def self.cred_read_w(target_name : Win32cr::Foundation::PWSTR, type__ : UInt32, flags : UInt32, credential : Win32cr::Security::Credentials::CREDENTIALW**) : Win32cr::Foundation::BOOL
      Win32cr::Security::Credentials.credReadW(target_name, type__, flags, credential)
    end

    def self.cred_write_w(credential : Win32cr::Security::Credentials::CREDENTIALW*, flags : UInt32) : Win32cr::Foundation::BOOL
      Win32cr::Security::Credentials.credWriteW(credential, flags)
    end

    def self.cred_delete_w(target_name : Win32cr::Foundation::PWSTR, type__ : UInt32, flags : UInt32) : Win32cr::Foundation::BOOL
      Win32cr::Security::Credentials.credDeleteW(target_name, type__, flags)
    end

    def self.cred_enumerate_w(filter : Win32cr::Foundation::PWSTR?, flags : Win32cr::Security::Credentials::CRED_ENUMERATE_FLAGS, count : UInt32*, credential : Win32cr::Security::Credentials::CREDENTIALW***) : Win32cr::Foundation::BOOL
      Win32cr::Security::Credentials.credEnumerateW(filter || Pointer(UInt16).null, flags, count, credential)
    end

    def self.cred_free(buffer : Void*) : Void
      Win32cr::Security::Credentials.credFree(buffer)
    end
  end
{% end %}
