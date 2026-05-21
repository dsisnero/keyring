require "./backend"
require "./config"
require "./credential"
require "./encryption"
require "./errors"
require "./logging"
require "./metrics"
require "./retryable"
require "./circuit_breaker"

{% if flag?(:linux) %}
  require "./kwallet_backend"
  require "./linux_backend"
{% end %}

{% if flag?(:darwin) %}
  require "./macos_backend"
{% end %}

{% if flag?(:windows) %}
  require "./windows_backend"
{% end %}

require "./file_backend"
require "./fail_backend"

module Keyring
  VERSION = "0.1.0"

  class Keyring
    getter backend : Backend
    getter config : Config

    # Class-level instance for module-level API (keyring=/keyring)
    @@current_keyring : Keyring? = nil

    # Backend limit filter (callable taking Backend.class, returning Bool)
    @@backend_limit : Proc(Backend.class, Bool)? = nil

    # Cache for backend availability checks across instances
    @@availability_cache = Hash(String, Bool).new
    # Test hook: override backend candidates list
    @@candidates_override : Array(Backend.class)? = nil

    # Circuit breakers keyed by backend class name
    @@circuit_breakers = Hash(String, CircuitBreaker).new

    # Retry configuration for backend operations
    property retry_config : Retryable::RetryConfig
    # Whether to enable automatic backend failover on persistent failure
    property? failover_enabled : Bool

    # Test helpers (no-ops in production unless called explicitly)
    def self.override_backend_candidates(candidates : Array(Backend.class)?)
      @@candidates_override = candidates
    end

    def self.reset_backend_overrides
      @@candidates_override = nil
      @@availability_cache.clear
      @@circuit_breakers.clear
    end

    # Reset all circuit breakers (test helper)
    def self.reset_circuit_breakers
      @@circuit_breakers.clear
    end

    # Get metrics for all tracked operations
    def self.metrics(backend : String? = nil, operation : String? = nil) : Hash(String, Metrics::Metric)
      Metrics.stats(backend, operation)
    end

    # Print metrics summary to log
    def self.metrics_summary : String
      Metrics.summary
    end

    # Set the current keyring backend for module-level API.
    # Mirrors Python keyring.set_keyring().
    def self.keyring=(backend : Backend)
      @@current_keyring = Keyring.new(backend: backend)
    end

    # Get the current keyring instance for module-level API.
    # Mirrors Python keyring.get_keyring().
    # Lazily initializes with auto-detected backend if not set.
    def self.keyring : Keyring
      @@current_keyring ||= Keyring.new
    end

    # Load a backend class by display name or class name.
    # Mirrors Python keyring.load_keyring() / _load_keyring_class().
    def self.load_keyring(keyring_name : String) : Backend
      candidates = @@candidates_override || get_candidate_list_static
      klass = candidates.find do |k|
        k.to_s.ends_with?(keyring_name) ||
          k.display_name.downcase == keyring_name.downcase
      end
      raise KeyringError.new("Backend not found: #{keyring_name}") unless klass
      raise KeyringError.new("Backend not viable: #{keyring_name}") unless klass.viable?
      klass.new
    end

    # Load a keyring configured in the environment variable.
    # Mirrors Python keyring.load_env().
    def self.load_env : Backend?
      if env = ENV["KEYRING_BACKEND"]?
        load_keyring(env)
      end
    rescue
      nil
    end

    # Load a keyring from the config file's preferred_backend setting.
    # Mirrors Python keyring.load_config().
    def self.load_config : Backend?
      Config.load.preferred_backend.try { |name| load_keyring(name) }
    rescue
      nil
    end

    # Return all viable backend instances (not just classes).
    # Mirrors Python keyring.backend.get_all_keyring().
    # ameba:disable Naming/AccessorMethodName
    def self.get_all_keyring : Array(Backend)
      candidates = @@candidates_override || get_candidate_list_static
      candidates
        .select(&.viable?)
        .compact_map { |klass|
          begin
            klass.new
          rescue
            nil
          end
        }
    end

    # Detect and initialize a backend with optional caller-supplied filter.
    # Mirrors Python keyring.core._detect_backend(limit).
    def self._detect_backend(limit : Proc(Backend.class, Bool)? = nil) : Backend
      @@backend_limit = limit
      # Try env, then config, then best available
      backend = load_env || load_config || best_available_backend
      backend
    end

    # Return the best available backend considering the limit filter.
    private def self.best_available_backend : Backend
      candidates = @@candidates_override || get_candidate_list_static
      if limit = @@backend_limit
        candidates = candidates.select(&limit)
      end
      klass = candidates.find(&.viable?)
      if klass
        klass.new
      else
        FailBackend.new
      end
    end

    # Get the static candidate list (not instance-dependent).
    # Uses the backend registry populated by Backend.register calls in each backend file.
    # ameba:disable Naming/AccessorMethodName
    private def self.get_candidate_list_static : Array(Backend.class)
      if Backend.registry.empty?
        build_default_candidates
      else
        Backend.registry
      end
    end

    # Build the default candidate list (used as fallback if registry is empty).
    private def self.build_default_candidates : Array(Backend.class)
      list = [] of Backend.class
      {% if flag?(:windows) %}
        list << WindowsBackend
      {% end %}
      {% if flag?(:darwin) %}
        list << MacOsKeyChainBackend
      {% end %}
      {% if flag?(:linux) %}
        list << LinuxSecretServiceBackend
        list << KWalletBackend
        list << KWallet4Backend
      {% end %}
      list << FileBackend
      list
    end

    # Get platform-appropriate candidate list (used internally)
    private def get_candidate_list : Array(Backend.class)
      if Backend.registry.empty?
        list = [] of Backend.class
        {% if flag?(:windows) %}
          list << WindowsBackend
        {% end %}
        {% if flag?(:darwin) %}
          list << MacOsKeyChainBackend
        {% end %}
        {% if flag?(:linux) %}
          list << LinuxSecretServiceBackend
          list << KWalletBackend
          list << KWallet4Backend
        {% end %}
        list << FileBackend
        list
      else
        Backend.registry
      end
    end

    def initialize(config_path : String? = nil, *, backend : Backend? = nil)
      @config = config_path ? Config.load(config_path) : Config.load
      ::Keyring.setup_logging(@config)
      @retry_config = Retryable.default
      @failover_enabled = true
      @backend = backend || get_preferred_backend
      Log.info { "Initialized keyring with backend: #{@backend.class}" }
    end

    def get_password(service : String, username : String) : String?
      validate_params(service, username)
      Log.debug { "Getting password for #{service}:#{username}" }
      cred = with_operation("get_password") { |backend| backend.get_credential(service, username) }
      return unless cred
      return unless password = cred.password
      if @config.encrypt_passwords? && (key = @config.encryption_key)
        Encryption.decrypt(password, key)
      else
        password
      end
    end

    def set_password(service : String, username : String, password : String)
      validate_params(service, username)
      raise KeyringError.new("Password cannot be empty") if password.empty?
      Log.debug { "Setting password for #{service}:#{username}" }
      cred = Credential.new(
        service: service,
        username: username,
        password: password,
        encryption_key: @config.encryption_key
      )
      with_operation("set_password") { |backend| backend.set_password(service, username, cred.password.as(String)) }
    end

    def update_password(service : String, username : String, new_password : String)
      validate_params(service, username)
      raise KeyringError.new("Password cannot be empty") if new_password.empty?
      # Verify credential exists before updating
      existing = get_credential(service, username)
      raise KeyringError.new("Credential not found: #{service}:#{username}") unless existing

      Log.debug { "Updating password for #{service}:#{username}" }
      set_password(service, username, new_password)
    end

    def delete_password(service : String, username : String)
      validate_params(service, username)
      Log.debug { "Deleting password for #{service}:#{username}" }
      with_operation("delete_password") { |backend| backend.delete_password(service, username) }
    end

    private def validate_params(service : String, username : String)
      raise KeyringError.new("Service name cannot be empty") if service.empty?
      raise KeyringError.new("Username cannot be empty") if username.empty?
    end

    def get_credential(service : String, username : String? = nil) : Credential?
      if username.nil? || username.empty?
        creds = list_credentials
        creds.find { |cred| cred.service == service }
      else
        with_operation("get_credential") { |backend| backend.get_credential(service, username) }
      end
    end

    def list_credentials : Array(Credential)
      with_operation("list_credentials") { |backend| backend.list_credentials }
    end

    # Execute a backend operation with retry, circuit breaker, metrics, and failover
    private def with_operation(operation : String, &block : Backend -> T) : T forall T
      Metrics.track(@backend.class.name, operation) do
        execute_on_backend(@backend, operation) { |backend| block.call(backend) }
      end
    end

    # Execute on a specific backend with circuit breaker and retry protection
    private def execute_on_backend(backend : Backend, operation : String, &block : Backend -> T) : T forall T
      breaker = circuit_breaker_for(backend)

      breaker.execute(operation) do
        Retryable.with_retry(@retry_config, "#{backend.class.name}.#{operation}") do
          block.call(backend)
        end
      end
    rescue ex : CircuitOpenError
      raise ex unless @failover_enabled

      Log.warn { "Circuit breaker open for #{backend.class.name}, attempting failover" }
      fallback = find_fallback_backend(backend)
      raise BackendError.new("All backends unavailable for #{operation}: #{ex.message}") unless fallback

      switch_backend(fallback)
      Retryable.with_retry(@retry_config, "#{fallback.class.name}.#{operation}") do
        block.call(fallback)
      end
    end

    # Find the circuit breaker for a backend (create if needed)
    private def circuit_breaker_for(backend : Backend) : CircuitBreaker
      name = backend.class.name
      @@circuit_breakers[name] ||= CircuitBreaker.new(name)
    end

    # Find an alternative backend to fail over to
    private def find_fallback_backend(current : Backend) : Backend?
      candidates = @@candidates_override || get_candidate_list

      current_name = current.class.name
      candidates.each do |klass|
        next if klass.name == current_name
        next unless available_cached?(klass)
        # Skip if this backend's circuit breaker is also open
        breaker = @@circuit_breakers[klass.name]?
        next if breaker && breaker.open?

        begin
          backend = initialize_backend_with_retry(klass, retries: 1)
          if backend_healthy?(backend)
            return backend
          end
        rescue
          next
        end
      end
      nil
    end

    # Switch to a new backend at runtime
    def switch_backend(new_backend : Backend)
      old_name = @backend.class.name
      @backend = new_backend
      Log.info { "Switched backend: #{old_name} -> #{new_backend.class.name}" }
    end

    def list_services : Array(String)
      list_credentials.map(&.service).uniq!
    end

    def list_usernames(service : String) : Array(String)
      list_credentials.select { |cred| cred.service == service }.map(&.username)
    end

    def search(query : String) : Array(Credential)
      list_credentials.select do |cred|
        cred.service.includes?(query) ||
          cred.username.includes?(query) ||
          cred.metadata.values.any?(&.includes?(query))
      end
    end

    def advanced_search(
      service : String? = nil,
      username : String? = nil,
      metadata : Hash(String, String)? = nil,
      created_after : Time? = nil,
    ) : Array(Credential)
      list_credentials.select do |cred|
        (service.nil? || cred.service == service) &&
          (username.nil? || cred.username == username) &&
          (metadata.nil? || metadata.all? { |k, v| cred.metadata[k]? == v }) &&
          (created_after.nil? || cred.created_at > created_after)
      end
    end

    def set_metadata(service : String, username : String, key : String, value : String)
      Log.debug { "Setting metadata for #{service}:#{username} - #{key}" }
      # If backend natively supports metadata, delegate to it
      if @backend.supports_metadata?
        @backend.set_metadata(service, username, key, value)
        return
      end
      # Fallback: mutate credential object (works for FileBackend)
      cred = get_credential(service, username)
      raise KeyringError.new("Credential not found: #{service}:#{username}") unless cred
      cred.add_metadata(key, value)
      # Re-save the credential with updated metadata
      set_password(service, username, cred.password.as(String))
    end

    def export_credentials(path : String)
      Log.info { "Exporting credentials to #{path}" }
      File.write(path, list_credentials.to_json)
    end

    def import_credentials(path : String)
      Log.info { "Importing credentials from #{path}" }
      credentials = Array(Credential).from_json(File.read(path))
      credentials.each do |cred|
        set_password(cred.service, cred.username, cred.password.as(String))
        cred.metadata.each do |k, v|
          set_metadata(cred.service, cred.username, k, v)
        end
      end
    end

    # List all available backend names for this platform
    def list_available_backends : Array(String)
      candidates = @@candidates_override || get_candidate_list
      candidates.select { |klass| available_cached?(klass) }.map(&.name)
    end

    # Switch to a named backend at runtime
    def switch_to_backend(name : String) : Backend
      candidates = @@candidates_override || get_candidate_list
      match = candidates.find { |klass| klass.name.ends_with?(name) || klass.name == name }
      raise KeyringError.new("Backend not found: #{name}") unless match
      raise KeyringError.new("Backend not available: #{name}") unless available_cached?(match)

      new_backend = initialize_backend_with_retry(match)
      raise KeyringError.new("Backend health check failed: #{name}") unless backend_healthy?(new_backend)

      switch_backend(new_backend)
      new_backend
    end

    # Backend limit filter (callable taking Backend.class, returning Bool)

    private def get_preferred_backend : Backend
      # 1) Construct candidate list for this platform (or test override)
      candidates = @@candidates_override || get_candidate_list

      # 2) Respect explicit preference if available
      if preferred = @config.preferred_backend
        if backend_class = candidates.find { |backend| backend.name.ends_with?(preferred) || backend.name == preferred }
          if available_cached?(backend_class)
            Log.info { "Selecting preferred backend: #{backend_class.name}" }
            return initialize_backend_with_retry(backend_class)
          else
            Log.warn { "Preferred backend #{preferred} not available" }
          end
        else
          Log.warn { "Preferred backend #{preferred} not recognized for this platform" }
        end
      end

      # 3) Apply configurable priority ordering if provided
      ordered = apply_priority(candidates, @config.backend_priority)
      Log.debug { "Backend selection order: #{ordered.map(&.name).join(", ")}" }

      # 4) Iterate candidates and choose the first healthy backend
      ordered.each do |backend_class_candidate|
        next unless available_cached?(backend_class_candidate)
        begin
          backend = initialize_backend_with_retry(backend_class_candidate)
          if backend_healthy?(backend)
            Log.info { "Selected backend: #{backend_class_candidate.name}" }
            return backend
          else
            Log.warn { "Backend health check failed for #{backend_class_candidate.name}, trying next" }
          end
        rescue ex
          Log.warn { "Failed to initialize backend #{backend_class_candidate.name}: #{ex.message}. Trying next." }
        end
      end

      Log.warn { "No healthy backend found, using FailBackend as fallback" }
      FailBackend.new
    end

    # Reorder candidates to honor configured priority. Unknown names are ignored.
    private def apply_priority(candidates : Array(Backend.class), priority : Array(String)?) : Array(Backend.class)
      return candidates if priority.nil? || priority.empty?
      prio_names = priority.map(&.downcase)
      selected = [] of Backend.class
      # Add those listed in priority if present in candidates
      prio_names.each do |name|
        if backend = candidates.find { |backend_candidate| backend_candidate.name.downcase.ends_with?(name) || backend_candidate.name.downcase == name }
          selected << backend unless selected.includes?(backend)
        end
      end
      # Append remaining candidates in their original order
      candidates.each do |backend|
        selected << backend unless selected.includes?(backend)
      end
      selected
    end

    private def available_cached?(backend_class : Backend.class) : Bool
      name = backend_class.name
      if (cached = @@availability_cache[name]?) != nil
        return cached.as(Bool)
      end
      available = false
      begin
        available = backend_class.available?
      rescue
        available = false
      end
      @@availability_cache[name] = available
      available
    end

    private def initialize_backend_with_retry(backend_class : Backend.class, retries : Int32 = 1) : Backend
      attempts = 0
      last_error : Exception? = nil
      while attempts <= retries
        attempts += 1
        begin
          Log.debug { "Initializing backend #{backend_class.name} (attempt #{attempts})" }
          return backend_class.new
        rescue ex
          last_error = ex
          if attempts <= retries
            Log.warn { "Initialization failed for #{backend_class.name}: #{ex.message}. Retrying..." }
          end
        end
      end
      raise last_error || raise("Unexpected: no error but retry exhausted")
    end

    private def backend_healthy?(backend : Backend) : Bool
      # Lightweight health check: attempt a metadata-free call
      backend.list_credentials
      true
    rescue ex
      Log.warn { "Health check error for #{backend.class}: #{ex.message}" }
      false
    end

    private def setup_logging
      Keyring.setup_logging(@config)
    end
  end

  def self.disable
    root = Platform.config_root
    Dir.mkdir_p(root)
    config_path = File.join(root, "config.yml")
    if File.exists?(config_path)
      raise KeyringError.new("Refusing to overwrite #{config_path}")
    end
    File.write(config_path, <<-YAML)
preferred_backend: NullBackend
YAML
  end
end
