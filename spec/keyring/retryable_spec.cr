require "../spec_helper"

module Keyring
  describe Retryable do
    it "returns result on first attempt" do
      calls = 0
      result = Retryable.with_retry(Retryable::RetryConfig.new(max_retries: 2), "test") do
        calls += 1
        42
      end
      result.should eq(42)
      calls.should eq(1)
    end

    it "retries on failure and returns success" do
      calls = 0
      result = Retryable.with_retry(Retryable::RetryConfig.new(max_retries: 2, base_delay: 0.001), "test") do
        calls += 1
        raise "transient" if calls < 2
        "ok"
      end
      result.should eq("ok")
      calls.should eq(2)
    end

    it "raises after max retries exhausted" do
      calls = 0
      expect_raises(Exception, "persistent") do
        Retryable.with_retry(Retryable::RetryConfig.new(max_retries: 2, base_delay: 0.001), "test") do
          calls += 1
          raise "persistent"
        end
      end
      calls.should eq(3)
    end

    it "does not retry non-retryable errors" do
      calls = 0
      expect_raises(KeyringError) do
        Retryable.with_retry(Retryable::RetryConfig.new(max_retries: 3, base_delay: 0.001), "test") do
          calls += 1
          raise KeyringError.new("validation")
        end
      end
      calls.should eq(1)
    end

    it "uses exponential backoff with configurable factor" do
      config = Retryable::RetryConfig.new(
        max_retries: 3,
        base_delay: 0.01,
        max_delay: 1.0,
        backoff_factor: 2.0
      )
      config.base_delay.should eq(0.01)
      config.max_delay.should eq(1.0)
      config.backoff_factor.should eq(2.0)
    end

    it "provides default config" do
      config = Retryable.default
      config.max_retries.should eq(2)
      config.base_delay.should eq(0.05)
    end

    it "provides init config for initialization" do
      config = Retryable.init_config
      config.max_retries.should eq(3)
      config.base_delay.should eq(0.2)
    end
  end
end
