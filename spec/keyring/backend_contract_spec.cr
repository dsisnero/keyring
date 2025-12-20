require "../spec_helper"

module Keyring
  # Minimal contract tests that every backend should satisfy
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
    end
  end

  describe "Backend contract suite" do
    # Run against MockBackend
    run_backend_contract(MockBackendFactory.new)
  end

  # Run against FileBackend using temp dir (separate group)
  describe "Backend contract: FileBackend" do
    dir = "/tmp/keyring-file-contract-#{Random.rand(1_000_000)}"
    Dir.mkdir_p(dir)
    run_backend_contract(FileBackendFactory.new(dir))
  end
end
