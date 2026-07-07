require "./credential"

module Keyring
  module SchemeSelectable
    SCHEMES = {
      "default"   => {"username" => "username", "service" => "service"},
      "KeePassXC" => {"username" => "UserName", "service" => "Title"},
    }

    property scheme : String = "default"

    def _query(service : String, username : String? = nil, **base) : Hash(String, String)
      s = SCHEMES[@scheme]
      result = {} of String => String
      base.each { |k, v| result[k.to_s] = v.to_s }
      if username
        result = result.merge({s["username"] => username})
      end
      result.merge({s["service"] => service})
    end
  end

  abstract class Backend
    # Registry of all backend subclasses (mirrors Python KeyringBackendMeta._classes)
    @@registry = [] of Backend.class

    def self.register(backend_class : Backend.class)
      @@registry << backend_class unless @@registry.includes?(backend_class)
    end

    def self.registry : Array(Backend.class)
      @@registry
    end

    def self.clear_registry
      @@registry.clear
    end

    # abstract def self.available? : Bool
    abstract def get_password(service : String, username : String) : String?
    abstract def set_password(service : String, username : String, password : String)
    abstract def delete_password(service : String, username : String)
    abstract def get_credential(service : String, username : String) : Credential?
    abstract def list_credentials : Array(Credential)

    # Backend priority: >= 1 is recommended, < 1 is optional/fallback
    # Mirrors Python KeyringBackend.priority classproperty.
    def self.priority : Float64
      0.0
    end

    def self.available? : Bool
      raise NotImplementedError.new("#{self}.available? must be implemented")
    end

    def self.display_name : String
      class_name = self.to_s
      parts = class_name.split("::")
      parts.last? ? parts.last.gsub(/([a-z])([A-Z])/, "\\1 \\2") : class_name
    end

    def self.viable? : Bool
      available?
    rescue
      false
    end

    @env_properties : Hash(String, String)?

    def env_properties : Hash(String, String)
      @env_properties ||= begin
        props = {} of String => String
        set_properties_from_env(props)
        props
      end
    end

    # Internal setter for dup copies via with_properties
    def env_properties=(props : Hash(String, String))
      @env_properties = props
    end

    # ameba:disable Naming/AccessorMethodName
    def set_properties_from_env(target : Hash(String, String)? = nil)
      props = target || env_properties
      ENV.each do |key, value|
        if key.starts_with?("KEYRING_PROPERTY_")
          name = key.lchop("KEYRING_PROPERTY_").downcase
          props[name] = value
        end
      end
    end

    def [](name : String) : String?
      env_properties[name]?
    end

    def with_properties(**properties : String) : self
      alt = self.dup
      props = {} of String => String
      env_properties.each { |k, v| props[k] = v }
      properties.each { |k, v| props[k.to_s] = v }
      alt.env_properties = props
      alt
    end

    # Optional capabilities
    def supports_metadata? : Bool
      false
    end

    # Optional: store a metadata key/value for an existing credential
    # Default: not supported
    def set_metadata(service : String, username : String, key : String, value : String)
      raise KeyringError.new("Metadata not supported by this backend")
    end
  end
end
