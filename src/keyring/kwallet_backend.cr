require "./backend"
require "./credential"
require "./errors"

module Keyring
  # KDE KWallet backend using D-Bus via qdbus CLI.
  # Supports KDE5 (org.kde.kwalletd5) and KDE4 (org.kde.kwalletd).
  #
  # Ported from: python-keyring keyring/backends/kwallet.py (v25.7.0)
  class KWalletBackend < Backend
    Backend.register(self)
    BUS_NAME       = "org.kde.kwalletd5"
    BUS_NAME_V4    = "org.kde.kwalletd"
    OBJECT_PATH    = "/modules/kwalletd5"
    OBJECT_PATH_V4 = "/modules/kwalletd"
    IFACE          = "org.kde.KWallet"
    APPID          = "Crystal keyring library"

    @bus_name : String
    @object_path : String
    @handle : Int32
    @connected : Bool

    def self.priority : Float64
      4.9
    end

    def self.available? : Bool
      return false unless system("which qdbus > /dev/null 2>&1")

      # Try KDE5, then KDE4
      bus = detect_bus
      return false unless bus

      begin
        # Check if KWallet service has an owner (actually running on the bus)
        output = qdbus("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.NameHasOwner", bus)
        output.strip == "true"
      rescue
        false
      end
    end

    def self.detect_bus : String?
      # Check if kwalletd5/kwalletd is running or activatable on the session bus
      begin
        output = qdbus("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.ListNames")
        return BUS_NAME if output.includes?(BUS_NAME)
        return BUS_NAME_V4 if output.includes?(BUS_NAME_V4)
      rescue
      end
      nil
    end

    def initialize
      @handle = -1
      @connected = false

      # Detect which KWallet version is available
      bus = self.class.detect_bus || BUS_NAME
      @bus_name = bus
      @object_path = bus == BUS_NAME ? OBJECT_PATH : OBJECT_PATH_V4
    end

    def get_password(service : String, username : String) : String?
      connected_or_raise!
      return nil unless has_entry?(service, username)
      read_password(service, username)
    end

    def set_password(service : String, username : String, password : String)
      connected_or_raise!
      write_password(service, username, password)
    end

    def delete_password(service : String, username : String)
      connected_or_raise!
      unless has_entry?(service, username)
        raise PasswordDeleteError.new("Password not found: #{service}:#{username}")
      end
      remove_entry(service, username)
    end

    def get_credential(service : String, username : String) : Credential?
      connected_or_raise!
      entries = entry_list(service)
      if entries.includes?(username)
        password = read_password(service, username)
        return Credential.new(service: service, username: username, password: password)
      end
      nil
    end

    def list_credentials : Array(Credential)
      # KWallet doesn't have a native list-all; iterate common services
      # This is a simplified implementation
      [] of Credential
    end

    private def connected?
      @connected && @handle >= 0 && open?
    end

    private def open? : Bool
      result = qdbus(@bus_name, @object_path, IFACE, "isOpen", @handle.to_s)
      result.strip == "true"
    rescue
      false
    end

    private def connected_or_raise!
      connect_if_needed
      raise KeyringLocked.new("Failed to unlock the keyring!") unless connected?
    end

    private def connect_if_needed
      return if connected?
      begin
        wallet = network_wallet
        @handle = open(wallet)
        @connected = @handle >= 0
      rescue
        @connected = false
      end
      @connected
    end

    private def ensure_connected!(service : String)
      return if @connected && @handle >= 0
      connect(service)
    end

    private def connect(service : String)
      wallet = network_wallet
      @handle = open(wallet)
      if @handle < 0
        raise InitError.new("Failed to open KWallet")
      end
      migrate(service) if service
      @connected = true
    rescue ex
      raise BackendError.new("Failed to open KWallet: #{ex.message}")
    end

    private def network_wallet : String
      qdbus(@bus_name, @object_path, IFACE, "networkWallet").strip
    end

    private def open(wallet : String) : Int32
      result = qdbus(@bus_name, @object_path, IFACE, "open", wallet, "0", APPID)
      result.strip.to_i32
    end

    private def has_entry?(service : String, username : String) : Bool
      result = qdbus(@bus_name, @object_path, IFACE, "hasEntry", @handle.to_s, service, username, APPID)
      result.strip == "true"
    end

    private def read_password(service : String, username : String) : String
      qdbus(@bus_name, @object_path, IFACE, "readPassword", @handle.to_s, service, username, APPID).strip
    end

    private def write_password(service : String, username : String, password : String)
      qdbus(@bus_name, @object_path, IFACE, "writePassword", @handle.to_s, service, username, password, APPID)
    rescue ex
      raise PasswordSetError.new("Failed to write password: #{ex.message}")
    end

    private def remove_entry(service : String, username : String)
      qdbus(@bus_name, @object_path, IFACE, "removeEntry", @handle.to_s, service, username, APPID)
    rescue ex
      raise PasswordDeleteError.new("Failed to delete password: #{ex.message}")
    end

    private def entry_list(service : String) : Array(String)
      result = qdbus(@bus_name, @object_path, IFACE, "entryList", @handle.to_s, service, APPID)
      result.strip.each_line.reject(&.empty?).to_a
    end

    private def migrate(service : String)
      old_folder = "Python"
      return unless has_folder?(old_folder)

      begin
        entries = read_password_list(old_folder, "*@*")
        entries.each do |key, password|
          parts = key.split('@', 2)
          next unless parts.size == 2
          username = parts[0]
          svc = parts[1]
          write_password(svc, username, password)
          remove_entry_from_folder(old_folder, key)
        end

        remaining = read_password_list(old_folder, "*")
        remove_folder(old_folder) if remaining.empty?
      rescue
        # Migration failure is non-fatal
      end
    end

    private def has_folder?(folder : String) : Bool
      result = qdbus(@bus_name, @object_path, IFACE, "hasFolder", @handle.to_s, folder, APPID)
      result.strip == "true"
    end

    private def read_password_list(folder : String, key : String) : Hash(String, String)
      result = qdbus(@bus_name, @object_path, IFACE, "readPasswordList", @handle.to_s, folder, key, APPID)
      hash = {} of String => String
      result.strip.each_line do |line|
        next if line.empty?
        parts = line.split(' ', 2)
        hash[parts[0]] = parts[1]? || "" if parts.size >= 1
      end
      hash
    end

    private def remove_entry_from_folder(folder : String, key : String)
      qdbus(@bus_name, @object_path, IFACE, "removeEntry", @handle.to_s, folder, key, APPID)
    end

    private def remove_folder(folder : String)
      qdbus(@bus_name, @object_path, IFACE, "removeFolder", @handle.to_s, folder, APPID)
    end

    def self.qdbus(*args : String) : String
      output = IO::Memory.new
      error = IO::Memory.new
      status = Process.run("qdbus", args: args.to_a, output: output, error: error)
      if status.success?
        output.to_s
      else
        err = error.to_s.strip
        raise KeyringError.new("qdbus error: #{err}") unless err.empty?
        raise KeyringError.new("qdbus failed with exit code #{status.exit_code}")
      end
    end

    private def qdbus(*args : String) : String
      # qdbus CLI expects interface.method as one argument: org.kde.KWallet.isEnabled
      # Many call sites pass them separately for readability: qdbus(bus, path, IFACE, "method", ...)
      # Detect and join: if third positional arg is an interface (contains '.') and fourth is a
      # simple method name (no '.'), combine them into one argument.
      call_args = if args.size >= 4 && args[2].includes?('.') && !args[3].includes?('.')
                    [args[0], args[1], "#{args[2]}.#{args[3]}"] + args[4..].to_a
                  else
                    args.to_a
                  end
      output = IO::Memory.new
      error = IO::Memory.new
      status = Process.run("qdbus", args: call_args, output: output, error: error)
      if status.success?
        output.to_s
      else
        err = error.to_s.strip
        raise KeyringError.new("qdbus error: #{err}") unless err.empty?
        raise KeyringError.new("qdbus failed with exit code #{status.exit_code}")
      end
    end
  end

  class KWallet4Backend < KWalletBackend
    BUS_NAME_V4 = "org.kde.kwalletd"

    def self.priority : Float64
      4.5
    end

    def self.available? : Bool
      return false unless system("which qdbus > /dev/null 2>&1")
      begin
        output = qdbus("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.NameHasOwner", BUS_NAME_V4)
        output.strip == "true"
      rescue
        false
      end
    end

    def initialize
      @handle = -1
      @connected = false
      @bus_name = "org.kde.kwalletd"
      @object_path = "/modules/kwalletd"
    end
  end
end
