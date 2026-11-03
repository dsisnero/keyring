require "../spec_helper"

module Keyring
  describe Platform do
    describe "config_root" do
      it "honors XDG_CONFIG_HOME on every platform" do
        custom = File.join(Dir.tempdir, "keyring-xdg-config")
        with_env("XDG_CONFIG_HOME", custom) do
          Platform.config_root.should eq(File.join(custom, "keyring_cr"))
        end
      end

      it "falls back to the platform location when XDG_CONFIG_HOME is unset" do
        {% if flag?(:windows) %}
          custom = File.join(Dir.tempdir, "keyring-localappdata-config")
          with_env("LOCALAPPDATA", custom) do
            with_env("XDG_CONFIG_HOME", nil) do
              Platform.config_root.should eq(File.join(custom, "Python Keyring"))
            end
          end
        {% else %}
          with_env("XDG_CONFIG_HOME", nil) do
            root = Platform.config_root
            root.should contain(".config")
            root.should contain("keyring_cr")
          end
        {% end %}
      end
    end

    describe "data_root" do
      it "honors XDG_DATA_HOME on every platform" do
        custom = File.join(Dir.tempdir, "keyring-xdg-data")
        with_env("XDG_DATA_HOME", custom) do
          Platform.data_root.should eq(File.join(custom, "keyring_cr"))
        end
      end

      it "falls back to the platform location when XDG_DATA_HOME is unset" do
        {% if flag?(:windows) %}
          custom = File.join(Dir.tempdir, "keyring-localappdata-data")
          with_env("LOCALAPPDATA", custom) do
            with_env("XDG_DATA_HOME", nil) do
              Platform.data_root.should eq(File.join(custom, "Python Keyring"))
            end
          end
        {% else %}
          with_env("XDG_DATA_HOME", nil) do
            root = Platform.data_root
            root.should contain(".local")
            root.should contain("keyring_cr")
          end
        {% end %}
      end
    end
  end
end
