require "../spec_helper"

module Keyring
  describe Platform do
    describe "config_root" do
      it "returns platform-specific config directory" do
        root = Platform.config_root
        root.should_not be_nil
        root.should_not be_empty
        root.should contain("keyring_cr")
      end

      it "respects XDG_CONFIG_HOME on unix" do
        custom = "/tmp/test-config"
        with_env("XDG_CONFIG_HOME", custom) do
          root = Platform.config_root
          root.should contain(custom)
          root.should contain("keyring_cr")
        end
      end

      it "falls back to ~/.config/keyring_cr on unix when XDG_CONFIG_HOME unset" do
        with_env("XDG_CONFIG_HOME", nil) do
          root = Platform.config_root
          root.should contain(".config")
          root.should contain("keyring_cr")
        end
      end
    end

    describe "data_root" do
      it "returns platform-specific data directory" do
        root = Platform.data_root
        root.should_not be_nil
        root.should_not be_empty
        root.should contain("keyring_cr")
      end

      it "respects XDG_DATA_HOME on unix" do
        custom = "/tmp/test-data"
        with_env("XDG_DATA_HOME", custom) do
          root = Platform.data_root
          root.should contain(custom)
          root.should contain("keyring_cr")
        end
      end

      it "falls back to ~/.local/share/keyring_cr on unix when XDG_DATA_HOME unset" do
        with_env("XDG_DATA_HOME", nil) do
          root = Platform.data_root
          root.should contain(".local")
          root.should contain("keyring_cr")
        end
      end
    end
  end
end
