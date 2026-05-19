require "../spec_helper"

module Keyring
  describe Metrics do
    before_each do
      Metrics.reset
    end

    it "tracks successful operations" do
      Metrics.track("TestBackend", "get_password") { "secret" }
      stats = Metrics.stats("TestBackend", "get_password")
      stats.size.should eq(1)
      metric = stats["TestBackend.get_password"]
      metric.count.should eq(1)
      metric.failure_count.should eq(0)
    end

    it "tracks failed operations" do
      expect_raises(Exception) do
        Metrics.track("TestBackend", "set_password") { raise "failed" }
      end
      stats = Metrics.stats("TestBackend")
      metric = stats["TestBackend.set_password"]
      metric.failure_count.should eq(1)
      metric.count.should eq(0)
    end

    it "tracks operation duration" do
      Metrics.track("TestBackend", "slow_op") do
        sleep(10.milliseconds)
        "done"
      end
      stats = Metrics.stats("TestBackend", "slow_op")
      metric = stats["TestBackend.slow_op"]
      metric.total_duration.should be > 0
      metric.min_duration.should be > 0
      metric.max_duration.should be > 0
    end

    it "filters stats by backend" do
      Metrics.track("BackendA", "get") { "a" }
      Metrics.track("BackendB", "get") { "b" }

      a_stats = Metrics.stats("BackendA")
      a_stats.size.should eq(1)
      a_stats.has_key?("BackendA.get").should be_true
    end

    it "filters stats by operation" do
      Metrics.track("MyBackend", "get_password") { "p" }
      Metrics.track("MyBackend", "set_password") { nil }

      get_stats = Metrics.stats(operation: "get_password")
      get_stats.size.should eq(1)
      get_stats.has_key?("MyBackend.get_password").should be_true
    end

    it "resets all metrics" do
      Metrics.track("Backend", "op") { "val" }
      Metrics.stats.size.should eq(1)

      Metrics.reset
      Metrics.stats.size.should eq(0)
    end

    it "generates summary string" do
      Metrics.track("Backend", "op") { "val" }
      summary = Metrics.summary
      summary.should contain("Backend.op")
      summary.should contain("calls=")
      summary.should contain("failures=")
    end

    it "calculates correct average duration" do
      3.times do |i|
        Metrics.track("Backend", "op") do
          sleep(((i + 1) * 1).milliseconds)
          "ok"
        end
      end
      stats = Metrics.stats("Backend")
      metric = stats["Backend.op"]
      metric.count.should eq(3)
      avg = metric.total_duration / metric.count
      avg.should be > 0
    end
  end
end
