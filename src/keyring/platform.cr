# Platform-specific data and config root directories.
# Follows upstream python-keyring keyring/util/platform_.py (v25.7.0),
# with one intentional extension: XDG variables win on every platform.
#
# - data_root: directory for credential storage
# - config_root: directory for configuration files
#
# If XDG_DATA_HOME / XDG_CONFIG_HOME are set (and non-empty), they are
# honored on Linux, macOS, and Windows. Otherwise:
# - Windows: %LOCALAPPDATA% or %ProgramData% / Python Keyring
# - Linux/macOS: ~/.local/share/keyring_cr and ~/.config/keyring_cr

module Keyring
  module Platform
    extend self

    # Returns the platform-specific data root directory.
    # XDG_DATA_HOME takes precedence on every platform when set.
    def data_root : String
      xdg_root("XDG_DATA_HOME") || platform_data_root
    end

    # Returns the platform-specific config root directory.
    # XDG_CONFIG_HOME takes precedence on every platform when set.
    def config_root : String
      xdg_root("XDG_CONFIG_HOME") || platform_config_root
    end

    # Returns $XDG_*_HOME/keyring_cr when the variable is set and non-empty.
    private def xdg_root(key : String) : String?
      base = ENV[key]?
      return nil if base.nil? || base.empty?
      File.join(base, "keyring_cr")
    end

    private def platform_data_root : String
      {% if flag?(:windows) %}
        data_root_windows
      {% else %}
        data_root_unix
      {% end %}
    end

    private def platform_config_root : String
      {% if flag?(:windows) %}
        data_root_windows
      {% else %}
        config_root_unix
      {% end %}
    end

    # Unix-style data root: ~/.local/share/keyring_cr
    private def data_root_unix : String
      base = ENV["HOME"]? || ""
      File.join(base, ".local", "share", "keyring_cr")
    end

    # Unix-style config root: ~/.config/keyring_cr
    private def config_root_unix : String
      base = ENV["HOME"]? || ""
      File.join(base, ".config", "keyring_cr")
    end

    # Windows data/config root: LOCALAPPDATA or ProgramData / Python Keyring
    private def data_root_windows : String
      base = ENV["LOCALAPPDATA"]? || ENV["ProgramData"]? || "."
      File.join(base, "Python Keyring")
    end
  end
end
