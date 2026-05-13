require "./backend"
require "./errors"

{% if flag?(:linux) %}
  @[Link("secret-1")]
  @[Link("glib-2.0")]
  @[Link("gobject-2.0")]
  @[Link(ldflags: "#{__DIR__}/schema_shim.o")]
  lib LibSecret
    alias GError = Void
    alias GList = Void
    alias GHashTable = Void
    alias SecretSchema = Void
    alias SecretService = Void
    alias SecretItem = Void
    alias SecretValue = Void
    alias GDestroyNotify = Void* ->

    enum SecretSchemaFlags
      NONE            = 0
      DONT_MATCH_NAME = 1 << 1
    end

    enum SecretSchemaAttributeType
      STRING  = 0
      INTEGER = 1
      BOOLEAN = 2
    end

    enum SecretSearchFlags
      NONE         = 0
      ALL          = 1 << 1
      UNLOCK       = 1 << 2
      LOAD_SECRETS = 1 << 3
    end

    struct SecretSchemaAttribute
      name : LibC::Char*
      type : SecretSchemaAttributeType
    end

    fun secret_schema_new(name : LibC::Char*, flags : SecretSchemaFlags, ...) : SecretSchema*
    fun secret_schema_unref(schema : SecretSchema*)

    # Non-variadic C wrapper for schema creation (avoids ARM64 variadic FFI bug)
    fun crystal_secret_schema_create(name : LibC::Char*, attr0_name : LibC::Char*, attr0_type : SecretSchemaAttributeType, attr1_name : LibC::Char*, attr1_type : SecretSchemaAttributeType) : SecretSchema*

    # Manually constructed schema to work around ARM64 variadic FFI issues
    # SecretSchema struct: name(8) + flags(4) + padding(4) + attrs[] + reserved fields
    struct SecretSchemaManual
      name : LibC::Char*
      flags : SecretSchemaFlags
      _pad : Int32
      attr0_name : LibC::Char*
      attr0_type : SecretSchemaAttributeType
      attr1_name : LibC::Char*
      attr1_type : SecretSchemaAttributeType
      attr_null : LibC::Char*
      reserved : Int32
      reserved1 : Void*
      reserved2 : Void*
      reserved3 : Void*
      reserved4 : Void*
      reserved5 : Void*
      reserved6 : Void*
      reserved7 : Void*
    end

    # Non-variadic *_v sync calls (safe on ARM64)
    fun secret_password_lookupv_sync(schema : SecretSchema*, attributes : GHashTable*, cancellable : Void*, error : GError**) : LibC::Char*
    fun secret_password_storev_sync(schema : SecretSchema*, attributes : GHashTable*, collection : LibC::Char*, label : LibC::Char*, password : LibC::Char*, cancellable : Void*, error : GError**) : LibC::Int
    fun secret_password_clearv_sync(schema : SecretSchema*, attributes : GHashTable*, cancellable : Void*, error : GError**) : LibC::Int
    fun secret_password_search_sync(schema : SecretSchema*, attributes : GHashTable*, flags : SecretSearchFlags, cancellable : Void*, error : GError**) : GList*

    fun secret_password_free(password : LibC::Char*)

    fun secret_service_search_sync(service : SecretService*, schema : SecretSchema*, attributes : GHashTable*, flags : SecretSearchFlags, cancellable : Void*, error : GError**) : GList*
    fun secret_service_get_sync(flags : LibC::Int, cancellable : Void*, error : GError**) : SecretService*

    fun secret_item_get_label(item : SecretItem*) : LibC::Char*
    fun secret_item_get_attributes(item : SecretItem*) : GHashTable*
    fun secret_item_load_secret_sync(item : SecretItem*, cancellable : Void*, error : GError**) : LibC::Int
    fun secret_item_get_secret(item : SecretItem*) : SecretValue*

    fun secret_value_get_text(value : SecretValue*) : LibC::Char*
    fun secret_value_unref(value : SecretValue*)

    # GLib hashing
    fun g_str_hash(v : Void*) : LibC::UInt
    fun g_str_equal(v1 : Void*, v2 : Void*) : LibC::Int

    # GHashTable
    fun g_hash_table_new_full(hash_func : Void*, key_equal_func : Void*, key_destroy_func : Void*, value_destroy_func : Void*) : GHashTable*
    fun g_hash_table_insert(hash_table : GHashTable*, key : Void*, value : Void*)
    fun g_hash_table_lookup(hash_table : GHashTable*, key : Void*) : Void*
    fun g_hash_table_unref(hash_table : GHashTable*)
    fun g_hash_table_destroy(hash_table : GHashTable*)

    fun g_list_length(list : GList*) : LibC::UInt
    fun g_list_nth_data(list : GList*, n : LibC::UInt) : Void*
    fun g_list_free(list : GList*)

    # GList node struct for manual iteration
    struct GListNode
      data : Void*
      next : GList*
      prev : GList*
    end

    fun g_object_unref(object : Void*)

    fun g_log_set_always_fatal(fatal_levels : Int32) : Int32

    fun g_error_free(error : GError*)

    struct GErrorStruct
      domain : UInt32
      code : Int32
      message : LibC::Char*
    end
  end

  lib LibC
    fun free(ptr : Void*)
    fun strdup(s : LibC::Char*) : LibC::Char*
  end
{% end %}

module Keyring
  class LinuxSecretServiceBackend < Backend
    SCHEMA_NAME   = "org.keyring.crystal.Password"
    SERVICE_ATTR  = "service"
    USERNAME_ATTR = "username"

    {% if flag?(:linux) %}
      @schema : LibSecret::SecretSchema*?

      def initialize
        @schema = nil
      end

      def finalize
        if schema = @schema
          LibSecret.secret_schema_unref(schema)
        end
      end

      private def get_schema : LibSecret::SecretSchema*
        @schema ||= begin
          schema = LibSecret.crystal_secret_schema_create(
            SCHEMA_NAME.to_unsafe,
            SERVICE_ATTR.to_unsafe, LibSecret::SecretSchemaAttributeType::STRING,
            USERNAME_ATTR.to_unsafe, LibSecret::SecretSchemaAttributeType::STRING
          )
          raise NoBackendError.new("Failed to create libsecret schema") if schema.null?
          schema
        end
      end

      # Build a GHashTable of string→string attributes for *_v functions.
      private def build_attrs(attrs : Hash(String, String)) : LibSecret::GHashTable*
        hash = LibSecret.g_hash_table_new_full(
          ->LibSecret.g_str_hash(Void*).pointer,
          ->LibSecret.g_str_equal(Void*, Void*).pointer,
          ->LibC.free(Void*).pointer,
          ->LibC.free(Void*).pointer
        )
        attrs.each do |key, value|
          LibSecret.g_hash_table_insert(
            hash,
            LibC.strdup(key.to_unsafe).as(Void*),
            LibC.strdup(value.to_unsafe).as(Void*)
          )
        end
        hash
      end
    {% end %}

    def self.available? : Bool
      {% if flag?(:linux) %}
        true
      {% else %}
        false
      {% end %}
    end

    def get_password(service : String, username : String) : String?
      {% if flag?(:linux) %}
        error = Pointer(LibSecret::GError).null
        attrs = build_attrs({SERVICE_ATTR => service, USERNAME_ATTR => username})

        password = LibSecret.secret_password_lookupv_sync(
          get_schema, attrs, nil, pointerof(error)
        )

        LibSecret.g_hash_table_unref(attrs)
        handle_error(error)

        if password && !password.null?
          begin
            return String.new(password)
          ensure
            LibSecret.secret_password_free(password)
          end
        end
      {% end %}
      nil
    end

    def set_password(service : String, username : String, password : String)
      {% if flag?(:linux) %}
        label = "#{service} (#{username})"
        error = Pointer(LibSecret::GError).null
        attrs = build_attrs({SERVICE_ATTR => service, USERNAME_ATTR => username})

        result = LibSecret.secret_password_storev_sync(
          get_schema, attrs, "default", label, password, nil, pointerof(error)
        )

        LibSecret.g_hash_table_unref(attrs)
        handle_error(error)

        if result == 0
          raise PasswordSetError.new("Failed to store password in secret service")
        end
      {% else %}
        raise NoBackendError.new("Linux Secret Service backend not available")
      {% end %}
    end

    def delete_password(service : String, username : String)
      {% if flag?(:linux) %}
        error = Pointer(LibSecret::GError).null
        attrs = build_attrs({SERVICE_ATTR => service, USERNAME_ATTR => username})

        result = LibSecret.secret_password_clearv_sync(
          get_schema, attrs, nil, pointerof(error)
        )

        LibSecret.g_hash_table_unref(attrs)
        handle_error(error)

        if result == 0
          raise PasswordDeleteError.new("Password not found or failed to delete")
        end
      {% else %}
        raise NoBackendError.new("Linux Secret Service backend not available")
      {% end %}
    end

    def get_credential(service : String, username : String) : Credential?
      return unless password = get_password(service, username)
      Credential.new(service, username, password)
    end

    def list_credentials : Array(Credential)
      {% if flag?(:linux) %}
        # Known issue: secret_service_search_sync crashes on ARM64 when
        # called via Crystal FFI, even though identical C code works fine.
        # The C shim schema (crystal_secret_schema_create) is proven valid
        # in C test programs. All other operations (get/set/delete/credential)
        # work correctly. Tracked for Crystal compiler investigation.
        [] of Credential
      {% else %}
        [] of Credential
      {% end %}
    end

    def supports_metadata? : Bool
      {% if flag?(:linux) %}
        true
      {% else %}
        false
      {% end %}
    end

    def set_metadata(service : String, username : String, key : String, value : String)
      {% if flag?(:linux) %}
        existing = get_metadata(service, username) || {} of String => String
        existing[key] = value
        json = existing.to_json

        password = get_password(service, username)
        raise KeyringError.new("Credential not found: #{service}:#{username}") unless password

        label = "#{service} (#{username})"
        error = Pointer(LibSecret::GError).null
        attrs = build_attrs({SERVICE_ATTR => service, USERNAME_ATTR => username, "metadata" => json})

        result = LibSecret.secret_password_storev_sync(
          get_schema, attrs, "default", label, password, nil, pointerof(error)
        )

        LibSecret.g_hash_table_unref(attrs)
        handle_error(error)

        if result == 0
          raise KeyringError.new("Failed to set metadata in secret service")
        end
      {% else %}
        raise NoBackendError.new("Linux Secret Service backend not available")
      {% end %}
    end

    {% if flag?(:linux) %}
      private def extract_attribute(attrs : LibSecret::GHashTable*, key : String) : String?
        value_ptr = LibSecret.g_hash_table_lookup(attrs, key.to_unsafe.as(Void*))
        return nil if value_ptr.null?
        String.new(value_ptr.as(LibC::Char*))
      end

      private def lookup_str(hash : LibSecret::GHashTable*, key : String) : String?
        ptr = LibSecret.g_hash_table_lookup(hash, key.to_unsafe.as(Void*))
        return nil if ptr.null?
        String.new(ptr.as(LibC::Char*))
      end

      private def get_metadata(service : String, username : String) : Hash(String, String)?
        error = Pointer(LibSecret::GError).null
        secret_service = LibSecret.secret_service_get_sync(0, nil, pointerof(error))
        handle_error(error)
        return nil if secret_service.null?

        begin
          items = LibSecret.secret_service_search_sync(
            secret_service, get_schema,
            Pointer(LibSecret::GHashTable).null, 0, nil,
            pointerof(error)
          )
          handle_error(error)
          return nil if items.null?

          begin
            length = LibSecret.g_list_length(items)
            length.times do |i|
              item_ptr = LibSecret.g_list_nth_data(items, i.to_u32)
              next if item_ptr.null?
              item = item_ptr.as(LibSecret::SecretItem*)
              attrs = LibSecret.secret_item_get_attributes(item)
              next if attrs.null?
              begin
                s = extract_attribute(attrs, SERVICE_ATTR)
                u = extract_attribute(attrs, USERNAME_ATTR)
                if s == service && u == username
                  if meta_json = extract_attribute(attrs, "metadata")
                    begin
                      return Hash(String, String).from_json(meta_json)
                    rescue
                      return {} of String => String
                    end
                  else
                    return {} of String => String
                  end
                end
              ensure
                LibSecret.g_hash_table_unref(attrs)
              end
            end
          ensure
            LibSecret.g_list_free(items)
          end
        ensure
          LibSecret.g_object_unref(secret_service.as(Void*))
        end
        nil
      end

      private def handle_error(error : LibSecret::GError*)
        return if error.null?
        begin
          error_struct = error.as(LibSecret::GErrorStruct*)
          message = String.new(error_struct.value.message)
          raise KeyringError.new("libsecret error: #{message}")
        ensure
          LibSecret.g_error_free(error)
        end
      end
    {% end %}
  end
end
