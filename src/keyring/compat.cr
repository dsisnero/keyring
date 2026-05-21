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
  end
{% end %}
