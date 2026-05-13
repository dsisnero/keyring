require "../spec_helper"

module Keyring
  UNICODE_CHARS = (
    "זהכיףסתםלשמועאיךתנצחקרפדעץטובבגן" \
    "ξεσκεπάζωτηνψυχοφθόραβδελυγμία" \
    "Съешьжеещёэтихмягкихфранцузскихбулокдавыпейчаю" \
    "Жълтатадюлябешещастливачепухъткойтоцъфназамръзнакатогьон"
  )

  DIFFICULT_CHARS = " \t\n\r\f\v!\"\#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
  ALPHABET        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

  def self.random_contract_str(k : Int32, source : String = ALPHABET) : String
    String.build(k) { |io| k.times { io << source[Random.rand(source.size)] } }
  end

  abstract struct BackendFactory
    abstract def make_backend : Backend
    abstract def name : String
  end

  struct MockBackendFactory < BackendFactory
    def make_backend : Backend
      MockBackend.new
    end

    def name : String
      "MockBackend"
    end
  end

  struct FileBackendFactory < BackendFactory
    def initialize(@tmp_dir : String)
    end

    def make_backend : Backend
      path = File.join(@tmp_dir, "credentials.enc.json")
      FileBackend.new(storage_path: path)
    end

    def name : String
      "FileBackend"
    end
  end

  # Run full backend contract test suite.
  # Original 3 Crystal tests + 10 upstream tests from
  # keyring/testing/backend.py BackendBasicTests (v25.7.0)
  def self.run_backend_contract(factory : BackendFactory)
    describe "Backend contract: #{factory.name}" do
      it "stores, retrieves, updates, deletes passwords" do
        backend = factory.make_backend
        service = "svc-#{Random.rand(10_000)}"
        user = "user-#{Random.rand(10_000)}"

        backend.get_password(service, user).should be_nil
        backend.set_password(service, user, "pw1")
        backend.get_password(service, user).should eq("pw1")

        backend.set_password(service, user, "pw2")
        backend.get_password(service, user).should eq("pw2")

        backend.delete_password(service, user)
        backend.get_password(service, user).should be_nil
      end

      it "lists credentials after inserts" do
        backend = factory.make_backend
        service = "l-svc-#{Random.rand(10_000)}"
        users = ["a", "b", "c"]
        users.each { |user| backend.set_password(service, user, "p-#{user}") }

        creds = backend.list_credentials
        found = creds.select { |cred| cred.service == service }
        found.map(&.username).sort!.should eq(users.sort)
      end

      it "get_credential returns full credential" do
        backend = factory.make_backend
        service = "svc-cred-#{Random.rand(10_000)}"
        user = "user-cred"
        backend.set_password(service, user, "pw")
        cred = backend.get_credential(service, user)
        cred.should_not be_nil
        unwrapped = cred.as(Credential)
        unwrapped.service.should eq(service)
        unwrapped.username.should eq(user)
        unwrapped.password.should eq("pw")
      end

      # -- Upstream BackendBasicTests (v25.7.0) --

      it "test_password_set_get" do
        backend = factory.make_backend
        pw = random_contract_str(20)
        un = random_contract_str(20)
        sv = random_contract_str(20)
        backend.get_password(sv, un).should be_nil
        backend.set_password(sv, un, pw)
        backend.get_password(sv, un).should eq(pw)
        backend.set_password(sv, un, "")
        backend.get_password(sv, un).should eq("")
        backend.delete_password(sv, un)
      end

      it "test_difficult_chars" do
        backend = factory.make_backend
        pw = random_contract_str(20, DIFFICULT_CHARS)
        un = random_contract_str(20, DIFFICULT_CHARS)
        sv = random_contract_str(20, DIFFICULT_CHARS)
        backend.get_password(sv, un).should be_nil
        backend.set_password(sv, un, pw)
        backend.get_password(sv, un).should eq(pw)
        backend.delete_password(sv, un)
      end

      it "test_delete_present" do
        backend = factory.make_backend
        pw = random_contract_str(20, DIFFICULT_CHARS)
        un = random_contract_str(20, DIFFICULT_CHARS)
        sv = random_contract_str(20, DIFFICULT_CHARS)
        backend.set_password(sv, un, pw)
        backend.delete_password(sv, un)
        backend.get_password(sv, un).should be_nil
      end

      it "test_delete_not_present" do
        backend = factory.make_backend
        un = random_contract_str(20)
        sv = random_contract_str(20)
        expect_raises(PasswordDeleteError) do
          backend.delete_password(sv, un)
        end
      end

      it "test_delete_one_in_group" do
        backend = factory.make_backend
        un1 = random_contract_str(20)
        un2 = random_contract_str(20)
        pw = random_contract_str(20)
        sv = random_contract_str(20)
        backend.set_password(sv, un1, pw)
        backend.set_password(sv, un2, pw)
        backend.delete_password(sv, un1)
        backend.get_password(sv, un2).should eq(pw)
        backend.delete_password(sv, un2)
      end

      it "test_unicode_chars" do
        backend = factory.make_backend
        pw = random_contract_str(20, UNICODE_CHARS)
        un = random_contract_str(20, UNICODE_CHARS)
        sv = random_contract_str(20, UNICODE_CHARS)
        backend.get_password(sv, un).should be_nil
        backend.set_password(sv, un, pw)
        backend.get_password(sv, un).should eq(pw)
        backend.delete_password(sv, un)
      end

      it "test_unicode_and_ascii_chars" do
        backend = factory.make_backend
        source = random_contract_str(10, UNICODE_CHARS) + random_contract_str(10) + random_contract_str(10, DIFFICULT_CHARS)
        pw = random_contract_str(20, source)
        un = random_contract_str(20, source)
        sv = random_contract_str(20, source)
        backend.get_password(sv, un).should be_nil
        backend.set_password(sv, un, pw)
        backend.get_password(sv, un).should eq(pw)
        backend.delete_password(sv, un)
      end

      it "test_different_user" do
        backend = factory.make_backend
        backend.set_password("service1", "user1", "password1")
        backend.set_password("service1", "user2", "password2")
        backend.get_password("service1", "user1").should eq("password1")
        backend.get_password("service1", "user2").should eq("password2")
        backend.set_password("service2", "user3", "password3")
        backend.get_password("service1", "user1").should eq("password1")
        backend.delete_password("service1", "user1")
        backend.delete_password("service1", "user2")
        backend.delete_password("service2", "user3")
      end

      it "test_credential" do
        backend = factory.make_backend
        cred = backend.get_credential("service", "nonexistent")
        cred.should be_nil

        backend.set_password("service1", "user1", "password1")
        backend.set_password("service1", "user2", "password2")

        cred = backend.get_credential("service1", "user2")
        cred.should_not be_nil
        cred.try(&.password).should eq("password2")
        backend.delete_password("service1", "user1")
        backend.delete_password("service1", "user2")
      end

      it "test_wrong_username_returns_none" do
        backend = factory.make_backend
        sv = "test_wrong_username_returns_none"
        backend.get_credential(sv, "nobody").should be_nil
        backend.set_password(sv, "user1", "password1")
        backend.set_password(sv, "user2", "password2")
        backend.get_credential(sv, "user1").try(&.password).should eq("password1")
        backend.get_credential(sv, "nobody!").should be_nil
        backend.delete_password(sv, "user1")
        backend.delete_password(sv, "user2")
      end
    end
  end

  describe "Backend contract suite" do
    run_backend_contract(MockBackendFactory.new)
  end

  describe "Backend contract: FileBackend" do
    dir = "/tmp/keyring-file-contract-#{Random.rand(1_000_000)}"
    Dir.mkdir_p(dir)
    run_backend_contract(FileBackendFactory.new(dir))
  end
end
