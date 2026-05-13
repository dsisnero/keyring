require "./backend"
require "./errors"

{% if flag?(:linux) %}
  @[Link("secret-1")]
  @[Link("glib-2.0")]
  @[Link("gobject-2.0")]
  lib LibSecret
    alias GError = Void*
    alias GList = Void*
    alias GHashTable = Void*
    alias SecretSchema = Void*
    alias SecretService = Void*
    alias SecretItem = Void*
    alias SecretValue = Void*

    enum SecretSchemaFlags
      NONE            = 0
      DONT_MATCH_NAME = 1 << 1
    end

    enum SecretSchemaAttributeType
      STRING  = 0
      INTEGER = 1
      BOOLEAN = 2
    end

    struct SecretSchemaAttribute
      name : LibC::Char*
      type : SecretSchemaAttributeType
    end

    fun secret_schema_new(name : LibC::Char*, flags : SecretSchemaFlags, ...) : SecretSchema*
    fun secret_schema_unref(schema : SecretSchema*)

    fun secret_password_store_sync(schema : SecretSchema*, collection : LibC::Char*, label : LibC::Char*,
                                   password : LibC::Char*, cancellable : Void*, error : GError**,
                                   ...) : LibC::Int

    fun secret_password_lookup_sync(schema : SecretSchema*, cancellable : Void*, error : GError**,
                                    ...) : LibC::Char*

    fun secret_password_clear_sync(schema : SecretSchema*, cancellable : Void*, error : GError**,
                                   ...) : LibC::Int

    fun secret_password_free(password : LibC::Char*)

    fun secret_service_search_sync(service : SecretService*, schema : SecretSchema*,
                                   attributes : GHashTable*, flags : LibC::Int,
                                   cancellable : Void*, error : GError**) : GList*

    fun secret_service_get_sync(flags : LibC::Int, cancellable : Void*, error : GError**) : SecretService*

    fun secret_item_get_label(item : SecretItem*) : LibC::Char*
    fun secret_item_get_attributes(item : SecretItem*) : GHashTable*
    fun secret_item_load_secret_sync(item : SecretItem*, cancellable : Void*, error : GError**) : LibC::Int
    fun secret_item_get_secret(item : SecretItem*) : SecretValue*

    fun secret_value_get_text(value : SecretValue*) : LibC::Char*
    fun secret_value_unref(value : SecretValue*)

    fun g_hash_table_lookup(hash_table : GHashTable*, key : Void*) : Void*
    fun g_hash_table_unref(hash_table : GHashTable*)

    fun g_list_length(list : GList*) : LibC::UInt
    fun g_list_nth_data(list : GList*, n : LibC::UInt) : Void*
    fun g_list_free_full(list : GList*, free_func : Void*)

    fun g_object_unref(object : Void*)

    fun g_error_free(error : GError*)

    struct GErrorStruct
      domain : UInt32
      code : Int32
      message : LibC::Char*
    end
  end

  lib LibC
    fun free(ptr : Void*)
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
          schema = LibSecret.secret_schema_new(
            SCHEMA_NAME,
            LibSecret::SecretSchemaFlags::NONE,
            SERVICE_ATTR, LibSecret::SecretSchemaAttributeType::STRING,
            USERNAME_ATTR, LibSecret::SecretSchemaAttributeType::STRING,
            Pointer(Void).null
          )
          raise NoBackendError.new("Failed to create libsecret schema") if schema.null?
          schema
        end
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
        password = LibSecret.secret_password_lookup_sync(
          get_schema,
          nil,
          pointerof(error),
          SERVICE_ATTR, service,
          USERNAME_ATTR, username,
          Pointer(Void).null
        )

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

        result = LibSecret.secret_password_store_sync(
          get_schema,
          "default",
          label,
          password,
          nil,
          pointerof(error),
          SERVICE_ATTR, service,
          USERNAME_ATTR, username,
          Pointer(Void).null
        )

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

        result = LibSecret.secret_password_clear_sync(
          get_schema,
          nil,
          pointerof(error),
          SERVICE_ATTR, service,
          USERNAME_ATTR, username,
          Pointer(Void).null
        )

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
        credentials = [] of Credential
        error = Pointer(LibSecret::GError).null

        service = LibSecret.secret_service_get_sync(0, nil, pointerof(error))
        handle_error(error)

        return credentials if service.null?

        begin
          items = LibSecret.secret_service_search_sync(
            service,
            get_schema,
            Pointer(LibSecret::GHashTable).null,
            0,
            nil,
            pointerof(error)
          )

          handle_error(error)

          return credentials if items.null?

          begin
            length = LibSecret.g_list_length(items)
            length.times do |i|
              item_ptr = LibSecret.g_list_nth_data(items, i.to_u32)
              next if item_ptr.null?

              item = item_ptr.as(LibSecret::SecretItem*)

              attrs = LibSecret.secret_item_get_attributes(item)
              next if attrs.null?

              begin
                service_name = extract_attribute(attrs, SERVICE_ATTR)
                username = extract_attribute(attrs, USERNAME_ATTR)
                metadata_json = extract_attribute(attrs, "metadata")
                metadata = {} of String => String
                if metadata_json
                  begin
                    metadata = Hash(String, String).from_json(metadata_json)
                  rescue
                    # ignore parse errors
                  end
                end

                if service_name && username
                  if LibSecret.secret_item_load_secret_sync(item, nil, pointerof(error)) != 0
                    secret_value = LibSecret.secret_item_get_secret(item)
                    if secret_value && !secret_value.null?
                      begin
                        password_ptr = LibSecret.secret_value_get_text(secret_value)
                        if password_ptr && !password_ptr.null?
                          password = String.new(password_ptr)
                          cred = Credential.new(service_name, username, password)
                          metadata.each { |k, v| cred.add_metadata(k, v) }
                          credentials << cred
                        end
                      ensure
                        LibSecret.secret_value_unref(secret_value)
                      end
                    end
                  end
                end
              ensure
                LibSecret.g_hash_table_unref(attrs)
              end
            end
          ensure
            LibSecret.g_list_free_full(items, ->LibSecret.g_object_unref(Void*).pointer)
          end
        ensure
          LibSecret.g_object_unref(service.as(Void*))
        end

        credentials
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
        # Retrieve existing metadata
        existing = get_metadata(service, username) || {} of String => String
        existing[key] = value
        json = existing.to_json

        # Preserve existing password
        password = get_password(service, username)
        raise KeyringError.new("Credential not found: #{service}:#{username}") unless password

        # Overwrite the item with updated attributes (libsecret will replace existing)
        label = "#{service} (#{username})"
        error = Pointer(LibSecret::GError).null
        result = LibSecret.secret_password_store_sync(
          get_schema,
          "default",
          label,
          password,
          nil,
          pointerof(error),
          SERVICE_ATTR, service,
          USERNAME_ATTR, username,
          "metadata", json,
          Pointer(Void).null
        )
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

      private def get_metadata(service : String, username : String) : Hash(String, String)?
        error = Pointer(LibSecret::GError).null
        secret_service = LibSecret.secret_service_get_sync(0, nil, pointerof(error))
        handle_error(error)
        return nil if secret_service.null?
        begin
          items = LibSecret.secret_service_search_sync(secret_service, get_schema, Pointer(LibSecret::GHashTable).null, 0, nil, pointerof(error))
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
            LibSecret.g_list_free_full(items, ->LibSecret.g_object_unref(Void*).pointer)
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
