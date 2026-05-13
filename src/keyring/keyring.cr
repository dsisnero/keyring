require "./backend"
require "./config"
require "./credential"
require "./encryption"
require "./errors"
require "./fail_backend"
require "./file_backend"
require "./logging"

{% if flag?(:linux) %}
  require "./linux_backend"
{% end %}

{% if flag?(:darwin) %}
  require "./macos_backend"
{% end %}

{% if flag?(:windows) %}
  require "./windows_backend"
{% end %}

module Keyring
  VERSION = "0.1.0"

  class Keyring
    getter backend : Backend
    getter config : Config

    # Class-level instance for module-level API (keyring=/keyring)
    @@current_keyring : Keyring? = nil

    # Cache for backend availability checks across instances
    @@availability_cache = Hash(String, Bool).new
    # Test hook: override backend candidates list
    @@candidates_override : Array(Backend.class)? = nil

    # Test helpers (no-ops in production unless called explicitly)
    def self.override_backend_candidates(candidates : Array(Backend.class)?)
      @@candidates_override = candidates
    end

    def self.reset_backend_overrides
      @@candidates_override = nil
      @@availability_cache.clear
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

    def initialize(config_path : String? = nil, *, backend : Backend? = nil)
      @config = config_path ? Config.load(config_path) : Config.load
      ::Keyring.setup_logging(@config)
      @backend = backend || get_preferred_backend
      Log.info { "Initialized keyring with backend: #{@backend.class}" }
    end

    def get_password(service : String, username : String) : String?
      validate_params(service, username)
      Log.debug { "Getting password for #{service}:#{username}" }
      return unless cred = get_credential(service, username)
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
      @backend.set_password(service, username, cred.password.as(String))
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
      @backend.delete_password(service, username)
    end

    private def validate_params(service : String, username : String)
      raise KeyringError.new("Service name cannot be empty") if service.empty?
      raise KeyringError.new("Username cannot be empty") if username.empty?
    end

    def get_credential(service : String, username : String) : Credential?
      @backend.get_credential(service, username)
    end

    def list_credentials : Array(Credential)
      @backend.list_credentials
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

    private def get_preferred_backend : Backend
      # 1) Construct candidate list for this platform (or test override)
      candidates = @@candidates_override || begin
        list = [] of Backend.class
        {% if flag?(:windows) %}
          list << WindowsBackend
        {% end %}
        {% if flag?(:darwin) %}
          list << MacOsKeyChainBackend
        {% end %}
        {% if flag?(:linux) %}
          list << LinuxSecretServiceBackend
        {% end %}
        list << FileBackend
        list
      end

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
end
