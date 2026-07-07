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

    it "_detect_backend returns highest priority viable backend" do
      Keyring::Keyring.reset_backend_overrides
      # Override candidates to test priority ordering.
      # Low-priority FileBackend vs high-priority LinuxSecretServiceBackend
      Keyring::Keyring.override_backend_candidates([
        Keyring::FileBackend,
        Keyring::LinuxSecretServiceBackend,
      ] of Keyring::Backend.class)

      backend = Keyring::Keyring._detect_backend
      # Priority: FileBackend=0.5, LinuxSecretServiceBackend=5.0
      # Highest priority should win
      backend.should be_a(Keyring::LinuxSecretServiceBackend)
    ensure
      Keyring::Keyring.reset_backend_overrides
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

      it "get_credential returns decrypted password" do
        config = TestHelpers.create_test_config(encrypt: true)
        kr = Keyring::Keyring.new(backend: Keyring::MockBackend.new, config: config)
        svc = "cred-enc-#{Random.rand(10_000)}"
        kr.set_password(svc, "user", "plain-pass")
        cred = kr.get_credential(svc, "user")
        cred.should_not be_nil
        cred.not_nil!.password.should eq("plain-pass")
      end

      it "update_password works with encryption" do
        config = TestHelpers.create_test_config(encrypt: true)
        kr = Keyring::Keyring.new(backend: Keyring::MockBackend.new, config: config)
        svc = "upd-enc-#{Random.rand(10_000)}"
        kr.set_password(svc, "user", "old-enc")
        kr.update_password(svc, "user", "new-enc")
        kr.get_password(svc, "user").should eq("new-enc")
      end

      it "export/import roundtrip preserves encrypted credentials" do
        config = TestHelpers.create_test_config(encrypt: true)
        kr = Keyring::Keyring.new(backend: Keyring::MockBackend.new, config: config)
        svc1 = "exp-svc1-#{Random.rand(10_000)}"
        svc2 = "exp-svc2-#{Random.rand(10_000)}"
        kr.set_password(svc1, "user1", "pass1")
        kr.set_password(svc2, "user2", "pass2")

        export_path = "/tmp/keyring-export-#{Random.rand(1_000_000)}.json"
        kr.export_credentials(export_path)

        # Import into new keyring instance
        kr2 = Keyring::Keyring.new(backend: Keyring::MockBackend.new, config: config)
        kr2.import_credentials(export_path)

        kr2.get_password(svc1, "user1").should eq("pass1")
        kr2.get_password(svc2, "user2").should eq("pass2")

        File.delete(export_path) if File.exists?(export_path)
      end

      it "set_metadata works with encrypted passwords" do
        config = TestHelpers.create_test_config(encrypt: true)
        kr = Keyring::Keyring.new(backend: Keyring::MockBackend.new, config: config)
        svc = "meta-enc-#{Random.rand(10_000)}"
        kr.set_password(svc, "user", "meta-pass")
        kr.set_metadata(svc, "user", "note", "test-value")

        cred = kr.get_credential(svc, "user")
        cred.should_not be_nil
        cred.not_nil!.metadata["note"].should eq("test-value")
        cred.not_nil!.password.should eq("meta-pass")
      end
    end

    describe "query methods" do
      it "list_services returns unique service names" do
        kr = Keyring::Keyring.new(backend: Keyring::MockBackend.new)
        kr.set_password("svc-a", "user1", "p1")
        kr.set_password("svc-a", "user2", "p2")
        kr.set_password("svc-b", "user3", "p3")

        services = kr.list_services
        services.sort.should eq(["svc-a", "svc-b"])
      end

      it "list_usernames returns usernames for a service" do
        kr = Keyring::Keyring.new(backend: Keyring::MockBackend.new)
        kr.set_password("svc-x", "alice", "p1")
        kr.set_password("svc-x", "bob", "p2")
        kr.set_password("svc-y", "charlie", "p3")

        kr.list_usernames("svc-x").sort.should eq(["alice", "bob"])
        kr.list_usernames("svc-y").should eq(["charlie"])
      end

      it "search finds credentials by service" do
        kr = Keyring::Keyring.new(backend: Keyring::MockBackend.new)
        kr.set_password("myapp-prod", "admin", "secret")
        kr.set_password("myapp-dev", "admin", "dev-secret")

        kr.search("prod").size.should eq(1)
        kr.search("myapp").size.should eq(2)
        kr.search("nope").size.should eq(0)
      end

      it "advanced_search filters by service and username" do
        kr = Keyring::Keyring.new(backend: Keyring::MockBackend.new)
        kr.set_password("app1", "alice", "p1")
        kr.set_password("app1", "bob", "p2")
        kr.set_password("app2", "alice", "p3")

        results = kr.advanced_search(service: "app1")
        results.size.should eq(2)

        results = kr.advanced_search(service: "app1", username: "alice")
        results.size.should eq(1)
        results[0].username.should eq("alice")
      end

      it "advanced_search filters by metadata" do
        kr = Keyring::Keyring.new(backend: Keyring::MockBackend.new)
        kr.set_password("app", "user1", "p1")
        kr.set_metadata("app", "user1", "env", "production")
        kr.set_password("app", "user2", "p2")
        kr.set_metadata("app", "user2", "env", "staging")

        results = kr.advanced_search(metadata: {"env" => "production"})
        results.size.should eq(1)
        results[0].username.should eq("user1")
      end

      it "advanced_search filters by created_after" do
        kr = Keyring::Keyring.new(backend: Keyring::MockBackend.new)
        kr.set_password("old", "user", "p1")
        sleep 10.milliseconds
        cutoff = Time.utc
        sleep 10.milliseconds
        kr.set_password("new", "user", "p2")

        results = kr.advanced_search(created_after: cutoff)
        results.size.should eq(1)
        results[0].service.should eq("new")
      end
    end

    describe "metadata persistence" do
      it "set_metadata fallback preserves existing metadata" do
        kr = Keyring::Keyring.new(backend: Keyring::MockBackend.new)
        kr.set_password("app", "user", "pass")
        kr.set_metadata("app", "user", "tag", "first")
        kr.set_metadata("app", "user", "env", "prod")

        cred = kr.get_credential("app", "user")
        cred.should_not be_nil
        cred.not_nil!.metadata["tag"].should eq("first")
        cred.not_nil!.metadata["env"].should eq("prod")
      end
    end
  end
end
