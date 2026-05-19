require "./logging"

module Keyring
  class CircuitBreaker
    enum State
      CLOSED
      OPEN
      HALF_OPEN
    end

    record Config,
      failure_threshold : Int32 = 5,
      recovery_timeout : Float64 = 30.0,
      half_open_max : Int32 = 1,
      window_duration : Float64 = 60.0

    getter name : String
    getter state : State
    getter config : Config
    getter failure_count : Int32
    getter success_count : Int32
    getter last_failure_time : Time?
    getter last_success_time : Time?
    getter opened_at : Time?

    def initialize(@name : String, @config : Config = Config.new)
      @state = State::CLOSED
      @failure_count = 0
      @success_count = 0
      @last_failure_time = nil
      @last_success_time = nil
      @opened_at = nil
      @half_open_tries = 0
    end

    # Execute a block through the circuit breaker.
    # Raises CircuitOpenError if circuit is open.
    def execute(operation : String, & : -> T) : T forall T
      case @state
      when State::OPEN
        raise CircuitOpenError.new("#{operation}: circuit breaker [#{@name}] is OPEN") unless recovery_elapsed?
        transition_to(State::HALF_OPEN)
        @half_open_tries = 0
      when State::HALF_OPEN
        raise CircuitOpenError.new("#{operation}: circuit breaker [#{@name}] HALF_OPEN max tries reached") if @half_open_tries >= @config.half_open_max
      end

      begin
        result = yield
        record_success
        result
      rescue ex
        record_failure
        raise ex
      end
    end

    def reset
      @state = State::CLOSED
      @failure_count = 0
      @success_count = 0
      @last_failure_time = nil
      @last_success_time = nil
      @opened_at = nil
      @half_open_tries = 0
    end

    def closed?
      @state.closed?
    end

    def open?
      @state.open?
    end

    def half_open?
      @state.half_open?
    end

    private def record_success
      @success_count += 1
      @last_success_time = Time.utc
      if @state.half_open?
        transition_to(State::CLOSED)
      end
      slide_window if @success_count + @failure_count > @config.failure_threshold * 2
    end

    private def record_failure
      @failure_count += 1
      @last_failure_time = Time.utc
      if @state.half_open?
        @half_open_tries += 1
        transition_to(State::OPEN)
      elsif @state.closed? && @failure_count >= @config.failure_threshold
        transition_to(State::OPEN)
      end
    end

    private def recovery_elapsed? : Bool
      return false unless opened = @opened_at
      (Time.utc - opened).total_seconds >= @config.recovery_timeout
    end

    private def transition_to(new_state : State)
      @state = new_state
      case new_state
      when State::OPEN
        @opened_at = Time.utc
        Log.warn { "Circuit breaker [#{@name}] OPENED after #{@failure_count} failures" }
      when State::CLOSED
        @failure_count = 0
        Log.info { "Circuit breaker [#{@name}] CLOSED (recovered)" }
      when State::HALF_OPEN
        Log.info { "Circuit breaker [#{@name}] HALF_OPEN (testing recovery)" }
      end
    end

    private def slide_window
      @failure_count = (@failure_count // 2)
      @success_count = (@success_count // 2)
    end
  end

  class CircuitOpenError < KeyringError
  end
end
