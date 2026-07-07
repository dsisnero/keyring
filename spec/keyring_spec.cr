require "./spec_helper"

describe Keyring do
  it "has a version number" do
    Keyring::VERSION.should_not be_nil
    Keyring::VERSION.should be_a(String)
  end

  describe "::Keyring" do
    it "initializes with default config" do
      keyring = Keyring::Keyring.new
      keyring.should be_a(Keyring::Keyring)
      keyring.backend.should be_a(Keyring::Backend)
      keyring.config.should be_a(Keyring::Config)
    end

    it "selects appropriate backend for platform" do
      keyring = Keyring::Keyring.new

      {% if flag?(:darwin) %}
        keyring.backend.should be_a(Keyring::MacOsKeyChainBackend)
      {% elsif flag?(:windows) %}
        keyring.backend.should be_a(Keyring::WindowsBackend)
      {% elsif flag?(:linux) %}
        keyring.backend.should be_a(Keyring::LinuxSecretServiceBackend)
      {% else %}
        keyring.backend.should be_a(Keyring::FileBackend)
      {% end %}
    end

    describe "validation" do
      it "raises error for empty service name" do
        keyring = Keyring::Keyring.new

        expect_raises(Keyring::KeyringError, /Service name cannot be empty/) do
          keyring.get_password("", "user")
        end
      end

      it "raises error for empty username" do
        keyring = Keyring::Keyring.new

        expect_raises(Keyring::KeyringError, /Username cannot be empty/) do
          keyring.get_password("service", "")
        end
      end

      it "raises error for empty password" do
        keyring = Keyring::Keyring.new

        expect_raises(Keyring::KeyringError, /Password cannot be empty/) do
          keyring.set_password("service", "user", "")
        end
      end
    end

    describe "#update_password" do
      it "updates existing password" do
        keyring = Keyring::Keyring.new
        service = "upd-svc-#{Random.rand(10_000)}"
        user = "upd-user"
        keyring.set_password(service, user, "old-pass")
        keyring.get_password(service, user).should eq("old-pass")

        keyring.update_password(service, user, "new-pass")
        keyring.get_password(service, user).should eq("new-pass")

        keyring.delete_password(service, user)
      end

      it "raises error if credential doesn't exist" do
        keyring = Keyring::Keyring.new
        expect_raises(Keyring::KeyringError, /not found/) do
          keyring.update_password("no-svc", "no-user", "pass")
        end
      end

      it "validates parameters" do
        keyring = Keyring::Keyring.new
        expect_raises(Keyring::KeyringError, /empty/) do
          keyring.update_password("", "user", "pass")
        end
        expect_raises(Keyring::KeyringError, /empty/) do
          keyring.update_password("svc", "", "pass")
        end
        expect_raises(Keyring::KeyringError, /empty/) do
          keyring.update_password("svc", "user", "")
        end
      end
    end
  end

  describe "module-level API" do
    it "load_env returns backend from KEYRING_BACKEND env" do
      with_env("KEYRING_BACKEND", "FileBackend") do
        backend = Keyring::Keyring.load_env
        backend.should be_a(Keyring::FileBackend)
      end
    end

    it "load_env returns nil when env not set" do
      with_env("KEYRING_BACKEND", nil) do
        Keyring::Keyring.load_env.should be_nil
      end
    end

    it "load_config returns backend from KEYRING_BACKEND env" do
      with_env("KEYRING_BACKEND", "FileBackend") do
        backend = Keyring::Keyring.load_config
        backend.should be_a(Keyring::FileBackend)
      end
    end

    it "load_keyring loads backend by class name" do
      backend = Keyring::Keyring.load_keyring("FileBackend")
      backend.should be_a(Keyring::FileBackend)
    end

    it "load_keyring raises for unknown backend" do
      expect_raises(Keyring::KeyringError, /not found/) do
        Keyring::Keyring.load_keyring("NonExistentBackend")
      end
    end

    it "get_all_keyring returns viable backends" do
      backends = Keyring::Keyring.get_all_keyring
      backends.should be_a(Array(Keyring::Backend))
      backends.should_not be_empty
    end

    it "disable creates config with NullBackend" do
      tmp = "/tmp/keyring-disable-#{Random.rand(1_000_000)}"
      cfg_dir = File.join(tmp, "keyring_cr")
      Dir.mkdir_p(cfg_dir)
      with_env("XDG_CONFIG_HOME", tmp) do
        Keyring.disable
        config_path = File.join(cfg_dir, "config.yml")
        File.exists?(config_path).should be_true
        File.read(config_path).should contain("NullBackend")
      end
      FileUtils.rm_rf(tmp) if Dir.exists?(tmp)
    end

    it "disable raises if config already exists" do
      tmp = "/tmp/keyring-disable2-#{Random.rand(1_000_000)}"
      cfg_dir = File.join(tmp, "keyring_cr")
      Dir.mkdir_p(cfg_dir)
      File.write(File.join(cfg_dir, "config.yml"), "existing: true\n")
      with_env("XDG_CONFIG_HOME", tmp) do
        expect_raises(Keyring::KeyringError, /Refusing to overwrite/) do
          Keyring.disable
        end
      end
      FileUtils.rm_rf(tmp) if Dir.exists?(tmp)
    end

    it "module-level keyring set/get/delete work" do
      backend = Keyring::MockBackend.new
      Keyring::Keyring.keyring = backend
      kr = Keyring::Keyring.keyring
      svc = "mod-api-#{Random.rand(10_000)}"
      kr.set_password(svc, "user", "pass")
      kr.get_password(svc, "user").should eq("pass")
      kr.delete_password(svc, "user")
      kr.get_password(svc, "user").should be_nil
    end

    it "_detect_backend respects limit filter" do
      Keyring::Keyring.reset_backend_overrides
      # Filter that excludes all backends
      none = Keyring::Keyring._detect_backend(->(_klass : Keyring::Backend.class) { false })
      none.should be_a(Keyring::FailBackend)
    end

    it "_detect_backend returns viable backend without limit" do
      Keyring::Keyring.reset_backend_overrides
      backend = Keyring::Keyring._detect_backend
      backend.should be_a(Keyring::Backend)
      (backend.is_a?(Keyring::FailBackend)).should be_false
    end

    it "recommended rejects low-priority backends" do
      Keyring::Keyring.recommended?(Keyring::NullBackend).should be_false
      Keyring::Keyring.recommended?(Keyring::FileBackend).should be_false
    end

    it "recommended accepts high-priority backends" do
      # LinuxSecretServiceBackend has priority 5.0 (recommended)
      {% if flag?(:linux) %}
        Keyring::Keyring.recommended?(Keyring::LinuxSecretServiceBackend).should be_true
      {% end %}
    end

    describe "encryption integration" do
      it "encrypts and decrypts password with symmetric SecretBox" do
        config = TestHelpers.create_test_config(encrypt: true)
        kr = Keyring::Keyring.new(backend: Keyring::MockBackend.new, config: config)
        svc = "enc-sym-#{Random.rand(10_000)}"
        kr.set_password(svc, "user", "secret123")
        kr.get_password(svc, "user").should eq("secret123")
      end

      it "encrypts and decrypts password with asymmetric CryptoBox" do
        kp = Keyring::Keypair.generate_encryption
        config = TestHelpers.create_test_config(encrypt: true)
        config.encryption_type = "asymmetric"
        config.encryption_public_key = kp.public_key
        config.encryption_secret_key = kp.secret_key
        kr = Keyring::Keyring.new(backend: Keyring::MockBackend.new, config: config)
        svc = "enc-asym-#{Random.rand(10_000)}"
        kr.set_password(svc, "user", "secret456")
        kr.get_password(svc, "user").should eq("secret456")
      end
    end
  end
end
