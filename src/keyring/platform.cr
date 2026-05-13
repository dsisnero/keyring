# Platform-specific data and config root directories.
# Follows upstream python-keyring keyring/util/platform_.py (v25.7.0).
#
# - data_root: directory for credential storage
# - config_root: directory for configuration files
#
# Uses XDG Base Directory Specification on Linux/macOS,
# Windows conventions on Windows.

module Keyring
  module Platform
    extend self

    # Returns the platform-specific data root directory.
    # - Windows: %LOCALAPPDATA% or %ProgramData% / Python Keyring
    # - Linux/macOS: $XDG_DATA_HOME or ~/.local/share / python_keyring
    def data_root : String
      {% if flag?(:windows) %}
        data_root_windows
      {% else %}
        data_root_unix
      {% end %}
    end

    # Returns the platform-specific config root directory.
    # - Windows: same as data_root
    # - Linux/macOS: $XDG_CONFIG_HOME or ~/.config / python_keyring
    def config_root : String
      {% if flag?(:windows) %}
        data_root
      {% else %}
        config_root_unix
      {% end %}
    end

    # Unix-style data root: XDG_DATA_HOME or ~/.local/share/python_keyring
    private def data_root_unix : String
      base = ENV["XDG_DATA_HOME"]? || File.join(ENV["HOME"]? || "", ".local", "share")
      File.join(base, "python_keyring")
    end

    # Unix-style config root: XDG_CONFIG_HOME or ~/.config/python_keyring
    private def config_root_unix : String
      base = ENV["XDG_CONFIG_HOME"]? || File.join(ENV["HOME"]? || "", ".config")
      File.join(base, "python_keyring")
    end

    # Windows data/config root: LOCALAPPDATA or ProgramData / Python Keyring
    private def data_root_windows : String
      base = ENV["LOCALAPPDATA"]? || ENV["ProgramData"]? || "."
      File.join(base, "Python Keyring")
    end
  end
end
