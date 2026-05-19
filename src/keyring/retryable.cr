require "./logging"

module Keyring
  module Retryable
    record RetryConfig,
      max_retries : Int32 = 3,
      base_delay : Float64 = 0.1,
      max_delay : Float64 = 5.0,
      backoff_factor : Float64 = 2.0

    # Types of errors that should NOT be retried (validation, not-found)
    NON_RETRYABLE = [
      KeyringError.name,
      "NoBackendError",
      "ConfigError",
      "EncryptionError",
    ]

    # Wrap a block with retry logic with exponential backoff.
    # Non-retryable errors (validation, config) are re-raised immediately.
    def self.with_retry(config : RetryConfig, operation : String, & : -> T) : T forall T
      delay = config.base_delay
      last_error : Exception? = nil

      (config.max_retries + 1).times do |attempt|
        begin
          return yield
        rescue ex
          last_error = ex

          # Don't retry validation/config errors
          unless retryable?(ex)
            raise ex
          end

          raise ex unless attempt < config.max_retries

          Log.warn { "#{operation} failed (attempt #{attempt + 1}/#{config.max_retries + 1}): #{ex.message}. Retrying in #{delay.round(2)}s..." }
          sleep(delay.seconds)
          delay = {delay * config.backoff_factor, config.max_delay}.min
        end
      end

      raise last_error || KeyringError.new("#{operation}: retry exhausted with no error")
    end

    # Default config for typical backend operations
    def self.default : RetryConfig
      RetryConfig.new(max_retries: 2, base_delay: 0.05, max_delay: 1.0)
    end

    # Config for initialization (more generous)
    def self.init_config : RetryConfig
      RetryConfig.new(max_retries: 3, base_delay: 0.2, max_delay: 3.0)
    end

    private def self.retryable?(ex : Exception) : Bool
      name = ex.class.name
      !NON_RETRYABLE.any? { |err_name| name.ends_with?(err_name) }
    end
  end
end
