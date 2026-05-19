require "../spec_helper"

module Keyring
  describe CircuitBreaker do
    it "starts in closed state" do
      breaker = CircuitBreaker.new("test")
      breaker.state.should eq(CircuitBreaker::State::CLOSED)
      breaker.closed?.should be_true
    end

    it "executes block successfully in closed state" do
      breaker = CircuitBreaker.new("test")
      result = breaker.execute("op") { 42 }
      result.should eq(42)
    end

    it "opens after failure threshold is reached" do
      config = CircuitBreaker::Config.new(failure_threshold: 3)
      breaker = CircuitBreaker.new("test", config)

      2.times do
        expect_raises(Exception) { breaker.execute("op") { raise "fail" } }
      end
      breaker.closed?.should be_true

      expect_raises(Exception) { breaker.execute("op") { raise "fail" } }
      breaker.open?.should be_true
    end

    it "raises CircuitOpenError when open" do
      config = CircuitBreaker::Config.new(failure_threshold: 1, recovery_timeout: 999.0)
      breaker = CircuitBreaker.new("test", config)

      expect_raises(Exception) { breaker.execute("op") { raise "fail" } }
      breaker.open?.should be_true

      expect_raises(CircuitOpenError) { breaker.execute("op") { "never" } }
    end

    it "transitions to half-open after recovery timeout" do
      config = CircuitBreaker::Config.new(failure_threshold: 1, recovery_timeout: 0.001)
      breaker = CircuitBreaker.new("test", config)

      expect_raises(Exception) { breaker.execute("op") { raise "fail" } }
      breaker.open?.should be_true

      sleep(5.milliseconds)

      result = breaker.execute("op") { "recovered" }
      result.should eq("recovered")
      breaker.closed?.should be_true
    end

    it "transitions back to open if half-open attempt fails" do
      config = CircuitBreaker::Config.new(failure_threshold: 1, recovery_timeout: 0.001)
      breaker = CircuitBreaker.new("test", config)

      expect_raises(Exception) { breaker.execute("op") { raise "fail" } }
      breaker.open?.should be_true

      sleep(5.milliseconds)

      expect_raises(Exception) { breaker.execute("op") { raise "fail again" } }
      breaker.open?.should be_true
    end

    it "resets to closed state" do
      config = CircuitBreaker::Config.new(failure_threshold: 1, recovery_timeout: 999.0)
      breaker = CircuitBreaker.new("test", config)

      expect_raises(Exception) { breaker.execute("op") { raise "fail" } }
      breaker.open?.should be_true

      breaker.reset
      breaker.closed?.should be_true
      breaker.failure_count.should eq(0)
      breaker.success_count.should eq(0)
    end

    it "tracks failure count" do
      breaker = CircuitBreaker.new("test")
      3.times do
        expect_raises(Exception) { breaker.execute("op") { raise "fail" } }
      end
      breaker.failure_count.should eq(3)
    end

    it "tracks success count" do
      breaker = CircuitBreaker.new("test")
      3.times { breaker.execute("op") { "ok" } }
      breaker.success_count.should eq(3)
    end

    it "accepts custom config" do
      config = CircuitBreaker::Config.new(
        failure_threshold: 10,
        recovery_timeout: 60.0,
        half_open_max: 3,
      )
      breaker = CircuitBreaker.new("custom", config)
      breaker.config.failure_threshold.should eq(10)
      breaker.config.recovery_timeout.should eq(60.0)
      breaker.config.half_open_max.should eq(3)
    end
  end
end
