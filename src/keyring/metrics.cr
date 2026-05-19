require "./logging"

module Keyring
  module Metrics
    record Metric,
      count : Int64 = 0,
      total_duration : Float64 = 0.0,
      min_duration : Float64 = Float64::MAX,
      max_duration : Float64 = 0.0,
      failure_count : Int64 = 0

    @@metrics = Hash(String, Metric).new

    # Track an operation with timing and success/failure
    def self.track(backend : String, operation : String, & : -> T) : T forall T
      key = "#{backend}.#{operation}"
      start = Time.instant
      begin
        result = yield
        elapsed = (Time.instant - start).total_seconds
        record(key, elapsed, success: true)
        result
      rescue ex
        elapsed = (Time.instant - start).total_seconds
        record(key, elapsed, success: false)
        raise ex
      end
    end

    def self.stats(backend : String? = nil, operation : String? = nil) : Hash(String, Metric)
      @@metrics.select do |key, _|
        match = true
        match &&= key.starts_with?(backend) if backend
        match &&= key.ends_with?(".#{operation}") if operation
        match
      end
    end

    def self.reset
      @@metrics.clear
    end

    def self.summary : String
      lines = [] of String
      @@metrics.each do |key, metric|
        avg = metric.count > 0 ? (metric.total_duration / metric.count) : 0.0
        pct = metric.count + metric.failure_count > 0 ? (metric.failure_count * 100 / (metric.count + metric.failure_count)) : 0.0
        lines << sprintf("%-40s calls=%-6d avg=%-8.3fs min=%-8.3fs max=%-8.3fs failures=%-4d (%-5.1f%%)",
          key, metric.count, avg, metric.min_duration == Float64::MAX ? 0.0 : metric.min_duration, metric.max_duration, metric.failure_count, pct)
      end
      lines.join("\n")
    end

    private def self.record(key : String, elapsed : Float64, success : Bool)
      metric = @@metrics[key]? || Metric.new
      if success
        metric = metric.copy_with(
          count: metric.count + 1,
          total_duration: metric.total_duration + elapsed,
          min_duration: {metric.min_duration, elapsed}.min,
          max_duration: {metric.max_duration, elapsed}.max,
        )
      else
        metric = metric.copy_with(failure_count: metric.failure_count + 1)
      end
      @@metrics[key] = metric
    end
  end
end
