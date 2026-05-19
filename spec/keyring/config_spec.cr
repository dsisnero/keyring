require "../spec_helper"

module Keyring
  describe Config do
    describe ".default_config_path" do
      it "returns platform-specific path" do
        path = Config.default_config_path
        path.should_not be_empty

        {% if flag?(:windows) %}
          path.should contain("keyring_cr")
          path.should contain("config.yml")
        {% else %}
          path.should contain("keyring_cr/config.yml")
        {% end %}
      end
    end

    describe ".new" do
      it "creates config with default values" do
        config = Config.new
        config.preferred_backend.should be_nil
        config.default_service.should be_nil
        config.encrypt_passwords?.should be_false # Default is false
        config.encryption_key.should be_nil
        config.log_level.should eq("INFO")
        config.log_file.should be_nil
      end
    end

    describe ".load" do
      it "returns new config when file doesn't exist" do
        config = Config.load("/nonexistent/path/config.yml")
        config.should be_a(Config)
        config.log_level.should eq("INFO")
      end

      it "loads config from YAML file" do
        yaml_content = <<-YAML
          preferred_backend: WindowsBackend
          default_service: TestApp
          encrypt_passwords: false
          log_level: DEBUG
        YAML

        File.write("/tmp/test_config.yml", yaml_content)

        config = Config.load("/tmp/test_config.yml")
        config.preferred_backend.should eq("WindowsBackend")
        config.default_service.should eq("TestApp")
        config.encrypt_passwords?.should be_false
        config.log_level.should eq("DEBUG")

        File.delete("/tmp/test_config.yml")
      end

      it "raises ConfigError for invalid YAML" do
        File.write("/tmp/invalid_config.yml", "invalid: yaml: content:")

        expect_raises(ConfigError, /Invalid config file/) do
          Config.load("/tmp/invalid_config.yml")
        end

        File.delete("/tmp/invalid_config.yml")
      end
    end

    describe "#save" do
      it "saves config to YAML file" do
        config = Config.new
        config.preferred_backend = "FileBackend"
        config.log_level = "WARN"
        config.encrypt_passwords = false # Disable encryption to avoid validation error

        path = "/tmp/test_save_config.yml"
        config.save(path)

        File.exists?(path).should be_true
        loaded = Config.load(path)
        loaded.preferred_backend.should eq("FileBackend")
        loaded.log_level.should eq("WARN")

        File.delete(path)
      end

      it "creates parent directories if needed" do
        config = Config.new
        path = "/tmp/keyring_test/nested/config.yml"

        config.save(path)
        File.exists?(path).should be_true

        File.delete(path)
        Dir.delete("/tmp/keyring_test/nested")
        Dir.delete("/tmp/keyring_test")
      end
    end

    describe "#validate!" do
      it "passes for valid config" do
        config = Config.new
        config.encryption_key = Encryption.generate_key

        config.validate!.should be_nil
      end

      it "raises error when encrypt_passwords is true but no key" do
        config = Config.new
        config.encrypt_passwords = true
        config.encryption_key = nil

        expect_raises(ConfigError, /encryption_key must be set/) do
          config.validate!
        end
      end

      it "raises error for invalid log level" do
        config = Config.new
        config.log_level = "INVALID"
        config.encrypt_passwords = false

        expect_raises(ConfigError, /Invalid log level/) do
          config.validate!
        end
      end

      it "accepts valid log levels" do
        config = Config.new
        config.encrypt_passwords = false

        ["DEBUG", "INFO", "WARN", "ERROR"].each do |level|
          config.log_level = level
          config.validate!.should be_nil
        end
      end
    end

    describe "environment variable support" do
      it "loads KEYRING_BACKEND env var" do
        ENV["KEYRING_BACKEND"] = "TestBackend"
        config = Config.new
        config.apply_env_overrides
        config.preferred_backend.should eq("TestBackend")
        ENV.delete("KEYRING_BACKEND")
      end

      it "loads KEYRING_LOG_LEVEL env var" do
        ENV["KEYRING_LOG_LEVEL"] = "DEBUG"
        config = Config.new
        config.apply_env_overrides
        config.log_level.should eq("DEBUG")
        ENV.delete("KEYRING_LOG_LEVEL")
      end

      it "loads KEYRING_ENCRYPTION_KEY env var" do
        ENV["KEYRING_ENCRYPTION_KEY"] = "test_key_value"
        config = Config.new
        config.apply_env_overrides
        config.encryption_key.should eq("test_key_value")
        ENV.delete("KEYRING_ENCRYPTION_KEY")
      end

      it "loads KEYRING_ENCRYPT env var" do
        ENV["KEYRING_ENCRYPT"] = "true"
        config = Config.new
        config.apply_env_overrides
        config.encrypt_passwords?.should be_true
        ENV.delete("KEYRING_ENCRYPT")
      end

      it "prioritizes env vars over file config" do
        with_temp_file("env_test") do |path|
          yaml_content = <<-YAML
            preferred_backend: FileBackend
            log_level: INFO
            encrypt_passwords: false
          YAML
          File.write(path, yaml_content)

          ENV["KEYRING_BACKEND"] = "EnvBackend"
          ENV["KEYRING_LOG_LEVEL"] = "WARN"

          config = Config.load(path)
          config.preferred_backend.should eq("EnvBackend")
          config.log_level.should eq("WARN")

          ENV.delete("KEYRING_BACKEND")
          ENV.delete("KEYRING_LOG_LEVEL")
        end
      end
    end
  end
end
