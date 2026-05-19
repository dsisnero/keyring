require "../spec_helper"

module Keyring
  # A backend that fails N times then succeeds
  class FlakyBackend < Backend
    getter get_failures : Int32 = 0
    getter set_failures : Int32 = 0

    property get_fail_count : Int32 = 3
    property set_fail_count : Int32 = 3

    def self.available? : Bool
      true
    end

    def get_password(service : String, username : String) : String?
      @get_failures += 1
      raise "transient get failure" if @get_failures <= @get_fail_count
      "secret"
    end

    def set_password(service : String, username : String, password : String)
      @set_failures += 1
      raise "transient set failure" if @set_failures <= @set_fail_count
    end

    def delete_password(service : String, username : String)
      raise BackendError.new("delete failed")
    end

    def get_credential(service : String, username : String) : Credential?
      get_password(service, username).try { |p| Credential.new(service: service, username: username, password: p) }
    end

    def list_credentials : Array(Credential)
      [] of Credential
    end
  end

  # A backend that always fails, for failover testing
  class AlwaysFailBackend < Backend
    def self.available? : Bool
      true
    end

    def get_password(service : String, username : String) : String?
      raise BackendError.new("always fails get")
    end

    def set_password(service : String, username : String, password : String)
      raise BackendError.new("always fails set")
    end

    def delete_password(service : String, username : String)
      raise BackendError.new("always fails delete")
    end

    def get_credential(service : String, username : String) : Credential?
      raise BackendError.new("always fails get_credential")
    end

    def list_credentials : Array(Credential)
      raise BackendError.new("always fails list")
    end
  end

  describe "Backend Reliability" do
    describe "retry on transient failures" do
      it "retries and succeeds on get_password" do
        backend = FlakyBackend.new
        keyring = Keyring.new(backend: backend)
        keyring.retry_config = Retryable::RetryConfig.new(max_retries: 3, base_delay: 0.001)

        result = keyring.get_password("svc", "usr")
        result.should eq("secret")
        backend.get_failures.should be > 0
      end

      it "retries and succeeds on set_password" do
        backend = FlakyBackend.new
        backend.set_fail_count = 2
        keyring = Keyring.new(backend: backend)
        keyring.retry_config = Retryable::RetryConfig.new(max_retries: 3, base_delay: 0.001)

        keyring.set_password("svc", "usr", "pwd")
        backend.set_failures.should be > 0
      end

      it "raises after max retries for persistently failing backend" do
        backend = FlakyBackend.new
        backend.get_fail_count = 99
        keyring = Keyring.new(backend: backend)
        keyring.retry_config = Retryable::RetryConfig.new(max_retries: 2, base_delay: 0.001)

        expect_raises(Exception) do
          keyring.get_password("svc", "usr")
        end
      end
    end

    describe "circuit breaker integration" do
      it "opens circuit after repeated failures" do
        Keyring.reset_backend_overrides
        Keyring.reset_circuit_breakers

        backend = AlwaysFailBackend.new
        keyring = Keyring.new(backend: backend)
        keyring.failover_enabled = false
        keyring.retry_config = Retryable::RetryConfig.new(max_retries: 0, base_delay: 0.001)

        # Cause failures to trigger circuit breaker
        5.times do
          expect_raises(BackendError) do
            keyring.get_password("svc", "usr")
          end
        end

        # Circuit should be open now
        expect_raises(CircuitOpenError) do
          keyring.get_password("svc", "usr")
        end
      end
    end

    describe "failover on circuit open" do
      it "switches to fallback backend when circuit is open" do
        Keyring.reset_backend_overrides
        Keyring.reset_circuit_breakers

        Keyring.override_backend_candidates(
          [MockBackend, AlwaysFailBackend] of Backend.class
        )

        backend = AlwaysFailBackend.new
        keyring = Keyring.new(backend: backend)
        keyring.retry_config = Retryable::RetryConfig.new(max_retries: 0, base_delay: 0.001)
        keyring.failover_enabled = false

        # Trigger enough failures to open the circuit
        circuit_opened = false
        6.times do
          begin
            keyring.get_password("svc", "usr")
          rescue CircuitOpenError
            circuit_opened = true
            break
          rescue BackendError
            # Expected while circuit is still closed
          end
        end

        circuit_opened.should be_true

        # Now enable failover - the next operation should switch to fallback
        keyring.failover_enabled = true

        # Should failover to MockBackend and work
        keyring.set_password("failover-test", "test-user", "test-pass")
        result = keyring.get_password("failover-test", "test-user")
        result.should eq("test-pass")
      end
    end

    describe "metrics integration" do
      it "tracks operation metrics" do
        backend = MockBackend.new
        keyring = Keyring.new(backend: backend)

        keyring.set_password("svc", "usr", "pwd")
        keyring.get_password("svc", "usr")

        stats = Keyring.metrics("Keyring::MockBackend")
        stats.has_key?("Keyring::MockBackend.set_password").should be_true
        stats.has_key?("Keyring::MockBackend.get_password").should be_true
        stats["Keyring::MockBackend.set_password"].count.should eq(1)
      end

      it "metrics summary contains expected info" do
        backend = MockBackend.new
        keyring = Keyring.new(backend: backend)
        keyring.set_password("svc", "usr", "pwd")

        summary = Keyring.metrics_summary
        summary.should contain("MockBackend")
      end
    end

    describe "failover configuration" do
      it "defaults failover to enabled" do
        backend = MockBackend.new
        keyring = Keyring.new(backend: backend)
        keyring.failover_enabled?.should be_true
      end

      it "can disable failover" do
        backend = MockBackend.new
        keyring = Keyring.new(backend: backend)
        keyring.failover_enabled = false
        keyring.failover_enabled?.should be_false
      end
    end
  end
end
