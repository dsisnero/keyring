require "./backend"
require "./errors"

{% if flag?(:darwin) %}
  @[Link(framework: "Security")]
  @[Link(framework: "CoreFoundation")]
  lib LibSecurity
    # OSStatus is Int32
    alias OSStatus = Int32

    # CoreFoundation types
    type CFStringRef = Void*
    type CFDictionaryRef = Void*
    type CFMutableDictionaryRef = Void*
    type CFDataRef = Void*
    type CFTypeRef = Void*
    type CFAllocatorRef = Void*
    type CFArrayRef = Void*

    # Constants for status codes
    ErrSecSuccess       =      0
    ErrSecItemNotFound  = -25300
    ErrSecDuplicateItem = -25299

    # SecItem functions
    fun sec_item_add = SecItemAdd(attributes : CFDictionaryRef, result : CFTypeRef*) : OSStatus
    fun sec_item_copy_matching = SecItemCopyMatching(query : CFDictionaryRef, result : CFTypeRef*) : OSStatus
    fun sec_item_update = SecItemUpdate(query : CFDictionaryRef, attributes_to_update : CFDictionaryRef) : OSStatus
    fun sec_item_delete = SecItemDelete(query : CFDictionaryRef) : OSStatus

    # CoreFoundation Dictionary functions
    fun cf_dictionary_create_mutable = CFDictionaryCreateMutable(allocator : CFAllocatorRef, capacity : LibC::Long, key_callbacks : Void*, value_callbacks : Void*) : CFMutableDictionaryRef
    fun cf_dictionary_set_value = CFDictionarySetValue(dict : CFMutableDictionaryRef, key : Void*, value : Void*)
    fun cf_dictionary_get_value = CFDictionaryGetValue(dict : CFDictionaryRef, key : Void*) : Void*

    # CoreFoundation Array functions
    fun cf_array_get_count = CFArrayGetCount(array : CFArrayRef) : LibC::Long
    fun cf_array_get_value_at_index = CFArrayGetValueAtIndex(array : CFArrayRef, idx : LibC::Long) : Void*

    # CoreFoundation String functions
    fun cf_string_create_with_cstring = CFStringCreateWithCString(allocator : CFAllocatorRef, cstr : UInt8*, encoding : UInt32) : CFStringRef
    fun cf_string_get_cstring = CFStringGetCString(string : CFStringRef, buffer : UInt8*, buffer_size : LibC::Long, encoding : UInt32) : Bool
    fun cf_string_get_length = CFStringGetLength(string : CFStringRef) : LibC::Long

    # CoreFoundation Data functions
    fun cf_data_create = CFDataCreate(allocator : CFAllocatorRef, bytes : UInt8*, length : LibC::Long) : CFDataRef
    fun cf_data_get_byte_ptr = CFDataGetBytePtr(data : CFDataRef) : UInt8*
    fun cf_data_get_length = CFDataGetLength(data : CFDataRef) : LibC::Long

    # CoreFoundation memory management
    fun cf_release = CFRelease(cf : CFTypeRef)
    fun cf_retain = CFRetain(cf : CFTypeRef) : CFTypeRef

    # kCFBooleanTrue
    $kCFBooleanTrue : CFTypeRef

    # String encoding (kCFStringEncodingUTF8 = 0x08000100)
    KCFStringEncodingUTF8 = 0x08000100_u32

    # Keychain attribute keys - extern const CFStringRef from Security framework
    $kSecClass : CFStringRef
    $kSecClassGenericPassword : CFStringRef
    $kSecAttrService : CFStringRef
    $kSecAttrAccount : CFStringRef
    $kSecValueData : CFStringRef
    $kSecReturnData : CFStringRef
    $kSecReturnAttributes : CFStringRef
    $kSecMatchLimit : CFStringRef
    $kSecMatchLimitOne : CFStringRef
    $kSecMatchLimitAll : CFStringRef
    $kSecAttrGeneric : CFStringRef
    $kSecAttrLabel : CFStringRef
  end

  # Helper module for CoreFoundation operations
  module CFHelper
    extend self

    # Create a CFString from a Crystal string
    def create_cfstring(str : String) : LibSecurity::CFStringRef
      LibSecurity.cf_string_create_with_cstring(
        Pointer(Void).null.as(LibSecurity::CFAllocatorRef),
        str.to_unsafe,
        LibSecurity::KCFStringEncodingUTF8
      )
    end

    # Convert CFString to Crystal String
    def cfstring_to_string(cf_str : LibSecurity::CFStringRef) : String?
      return nil if cf_str.null?

      length = LibSecurity.cf_string_get_length(cf_str)
      buffer = Bytes.new(length * 4 + 1) # UTF-8 can be up to 4 bytes per character

      if LibSecurity.cf_string_get_cstring(cf_str, buffer.to_unsafe, buffer.size, LibSecurity::KCFStringEncodingUTF8)
        String.new(buffer.to_unsafe)
      else
        nil
      end
    end

    # Create CFData from bytes
    def create_cfdata(data : Bytes) : LibSecurity::CFDataRef
      LibSecurity.cf_data_create(Pointer(Void).null.as(LibSecurity::CFAllocatorRef), data.to_unsafe, data.size)
    end

    # Convert CFData to Bytes
    def cfdata_to_bytes(cf_data : LibSecurity::CFDataRef) : Bytes?
      return nil if cf_data.null?

      ptr = LibSecurity.cf_data_get_byte_ptr(cf_data)
      length = LibSecurity.cf_data_get_length(cf_data)

      Bytes.new(ptr, length.to_i)
    end

    # Create a mutable dictionary
    def create_mutable_dict : LibSecurity::CFMutableDictionaryRef
      LibSecurity.cf_dictionary_create_mutable(
        Pointer(Void).null.as(LibSecurity::CFAllocatorRef),
        0_i64,
        Pointer(Void).null,
        Pointer(Void).null
      )
    end

    # Set dictionary value
    def dict_set(dict : LibSecurity::CFMutableDictionaryRef, key : Void*, value : Void*)
      LibSecurity.cf_dictionary_set_value(dict, key, value)
    end
  end
{% end %}

module Keyring
  class MacOsKeyChainBackend < Backend
    Backend.register(self)
    KEYCHAIN_NAME = "keyring"

    def supports_metadata? : Bool
      true
    end

    # Note: This flag is kept for API compatibility but has no effect with C API implementation
    # The C API doesn't have a direct equivalent to the command-line -A flag
    # For development, use "Always Allow" in permission dialogs or code sign your app
    # Note: Implement proper kSecAttrAccessible support for access control
    class_property? allow_any_access : Bool = false

    def self.available? : Bool
      {% if flag?(:darwin) %}
        # Check if Security framework is available
        true
      {% else %}
        false
      {% end %}
    end

    def get_password(service : String, username : String) : String?
      {% if flag?(:darwin) %}
        # Create query dictionary
        query = CFHelper.create_mutable_dict

        # Set query attributes
        CFHelper.dict_set(query, LibSecurity.kSecClass.as(Void*), LibSecurity.kSecClassGenericPassword.as(Void*))

        service_ref = CFHelper.create_cfstring(service)
        CFHelper.dict_set(query, LibSecurity.kSecAttrService.as(Void*), service_ref.as(Void*))

        account_ref = CFHelper.create_cfstring(username)
        CFHelper.dict_set(query, LibSecurity.kSecAttrAccount.as(Void*), account_ref.as(Void*))

        # Request password data
        CFHelper.dict_set(query, LibSecurity.kSecReturnData.as(Void*), LibSecurity.kCFBooleanTrue.as(Void*))

        # Limit to one result
        CFHelper.dict_set(query, LibSecurity.kSecMatchLimit.as(Void*), LibSecurity.kSecMatchLimitOne.as(Void*))

        # Execute query - IMPORTANT: Pass address of result variable, not null pointer
        result = Pointer(Void).null.as(LibSecurity::CFTypeRef)
        status = LibSecurity.sec_item_copy_matching(query.as(LibSecurity::CFDictionaryRef), pointerof(result))

        # Clean up query and inputs
        LibSecurity.cf_release(query.as(LibSecurity::CFTypeRef))
        LibSecurity.cf_release(service_ref.as(LibSecurity::CFTypeRef))
        LibSecurity.cf_release(account_ref.as(LibSecurity::CFTypeRef))

        if status == LibSecurity::ErrSecSuccess && !result.null?
          # Copy bytes to String BEFORE releasing CFData
          if bytes = CFHelper.cfdata_to_bytes(result.as(LibSecurity::CFDataRef))
            password = String.new(bytes)
            LibSecurity.cf_release(result)
            return password
          else
            LibSecurity.cf_release(result)
          end
        end

        nil
      {% else %}
        raise NoBackendError.new("macOS backend not available on this platform")
      {% end %}
    end

    def set_password(service : String, username : String, password : String)
      {% if flag?(:darwin) %}
        # Try to update first
        query = CFHelper.create_mutable_dict
        CFHelper.dict_set(query, LibSecurity.kSecClass.as(Void*), LibSecurity.kSecClassGenericPassword.as(Void*))

        service_ref = CFHelper.create_cfstring(service)
        CFHelper.dict_set(query, LibSecurity.kSecAttrService.as(Void*), service_ref.as(Void*))

        account_ref = CFHelper.create_cfstring(username)
        CFHelper.dict_set(query, LibSecurity.kSecAttrAccount.as(Void*), account_ref.as(Void*))

        # Create update attributes
        update_attrs = CFHelper.create_mutable_dict
        password_data = CFHelper.create_cfdata(password.to_slice)
        CFHelper.dict_set(update_attrs, LibSecurity.kSecValueData.as(Void*), password_data.as(Void*))

        # Try update
        status = LibSecurity.sec_item_update(
          query.as(LibSecurity::CFDictionaryRef),
          update_attrs.as(LibSecurity::CFDictionaryRef)
        )

        LibSecurity.cf_release(update_attrs.as(LibSecurity::CFTypeRef))

        if status == LibSecurity::ErrSecItemNotFound
          # Item doesn't exist, add it
          LibSecurity.cf_release(query.as(LibSecurity::CFTypeRef))

          # Create add attributes
          add_attrs = CFHelper.create_mutable_dict
          CFHelper.dict_set(add_attrs, LibSecurity.kSecClass.as(Void*), LibSecurity.kSecClassGenericPassword.as(Void*))
          CFHelper.dict_set(add_attrs, LibSecurity.kSecAttrService.as(Void*), service_ref.as(Void*))
          CFHelper.dict_set(add_attrs, LibSecurity.kSecAttrAccount.as(Void*), account_ref.as(Void*))
          CFHelper.dict_set(add_attrs, LibSecurity.kSecValueData.as(Void*), password_data.as(Void*))

          # Note: For development mode (allow_any_access), we could set kSecAttrAccessible
          # but this requires additional constants and doesn't directly map to -A flag
          # The C API approach still requires "Always Allow" for repeated access

          status = LibSecurity.sec_item_add(add_attrs.as(LibSecurity::CFDictionaryRef), Pointer(Void).null.as(LibSecurity::CFTypeRef*))

          LibSecurity.cf_release(add_attrs.as(LibSecurity::CFTypeRef))
        else
          LibSecurity.cf_release(query.as(LibSecurity::CFTypeRef))
        end

        LibSecurity.cf_release(service_ref.as(LibSecurity::CFTypeRef))
        LibSecurity.cf_release(account_ref.as(LibSecurity::CFTypeRef))
        LibSecurity.cf_release(password_data.as(LibSecurity::CFTypeRef))

        unless status == LibSecurity::ErrSecSuccess
          raise PasswordSetError.new("Failed to store password in macOS Keychain (status: #{status})")
        end
      {% else %}
        raise NoBackendError.new("macOS backend not available on this platform")
      {% end %}
    end

    def delete_password(service : String, username : String)
      {% if flag?(:darwin) %}
        query = CFHelper.create_mutable_dict
        CFHelper.dict_set(query, LibSecurity.kSecClass.as(Void*), LibSecurity.kSecClassGenericPassword.as(Void*))

        service_ref = CFHelper.create_cfstring(service)
        CFHelper.dict_set(query, LibSecurity.kSecAttrService.as(Void*), service_ref.as(Void*))

        account_ref = CFHelper.create_cfstring(username)
        CFHelper.dict_set(query, LibSecurity.kSecAttrAccount.as(Void*), account_ref.as(Void*))

        status = LibSecurity.sec_item_delete(query.as(LibSecurity::CFDictionaryRef))

        LibSecurity.cf_release(query.as(LibSecurity::CFTypeRef))
        LibSecurity.cf_release(service_ref.as(LibSecurity::CFTypeRef))
        LibSecurity.cf_release(account_ref.as(LibSecurity::CFTypeRef))

        if status == LibSecurity::ErrSecItemNotFound
          raise PasswordDeleteError.new("Password not found in macOS Keychain")
        elsif status != LibSecurity::ErrSecSuccess
          raise PasswordDeleteError.new("Failed to delete password from macOS Keychain (status: #{status})")
        end
      {% else %}
        raise NoBackendError.new("macOS backend not available on this platform")
      {% end %}
    end

    def set_metadata(service : String, username : String, key : String, value : String)
      {% if flag?(:darwin) %}
        # Merge existing metadata with new key/value and update kSecAttrGeneric
        meta = fetch_metadata(service, username) || {} of String => String
        meta[key] = value
        json = meta.to_json
        data = CFHelper.create_cfdata(json.to_slice)

        # Build query to identify the item
        query = CFHelper.create_mutable_dict
        CFHelper.dict_set(query, LibSecurity.kSecClass.as(Void*), LibSecurity.kSecClassGenericPassword.as(Void*))
        service_ref = CFHelper.create_cfstring(service)
        account_ref = CFHelper.create_cfstring(username)
        CFHelper.dict_set(query, LibSecurity.kSecAttrService.as(Void*), service_ref.as(Void*))
        CFHelper.dict_set(query, LibSecurity.kSecAttrAccount.as(Void*), account_ref.as(Void*))

        # Build update dict
        update = CFHelper.create_mutable_dict
        CFHelper.dict_set(update, LibSecurity.kSecAttrGeneric.as(Void*), data.as(Void*))

        status = LibSecurity.sec_item_update(query.as(LibSecurity::CFDictionaryRef), update.as(LibSecurity::CFDictionaryRef))

        # Cleanup
        LibSecurity.cf_release(update.as(LibSecurity::CFTypeRef))
        LibSecurity.cf_release(query.as(LibSecurity::CFTypeRef))
        LibSecurity.cf_release(service_ref.as(LibSecurity::CFTypeRef))
        LibSecurity.cf_release(account_ref.as(LibSecurity::CFTypeRef))
        LibSecurity.cf_release(data.as(LibSecurity::CFTypeRef))

        unless status == LibSecurity::ErrSecSuccess
          raise KeyringError.new("Failed to set metadata in macOS Keychain (status: #{status})")
        end
      {% else %}
        raise NoBackendError.new("macOS backend not available on this platform")
      {% end %}
    end

    private def fetch_metadata(service : String, username : String) : Hash(String, String)?
      {% if flag?(:darwin) %}
        # Query attributes only
        query = CFHelper.create_mutable_dict
        CFHelper.dict_set(query, LibSecurity.kSecClass.as(Void*), LibSecurity.kSecClassGenericPassword.as(Void*))
        service_ref = CFHelper.create_cfstring(service)
        account_ref = CFHelper.create_cfstring(username)
        CFHelper.dict_set(query, LibSecurity.kSecAttrService.as(Void*), service_ref.as(Void*))
        CFHelper.dict_set(query, LibSecurity.kSecAttrAccount.as(Void*), account_ref.as(Void*))
        CFHelper.dict_set(query, LibSecurity.kSecReturnAttributes.as(Void*), LibSecurity.kCFBooleanTrue.as(Void*))
        CFHelper.dict_set(query, LibSecurity.kSecMatchLimit.as(Void*), LibSecurity.kSecMatchLimitOne.as(Void*))

        result = Pointer(Void).null.as(LibSecurity::CFTypeRef)
        status = LibSecurity.sec_item_copy_matching(query.as(LibSecurity::CFDictionaryRef), pointerof(result))

        LibSecurity.cf_release(query.as(LibSecurity::CFTypeRef))
        LibSecurity.cf_release(service_ref.as(LibSecurity::CFTypeRef))
        LibSecurity.cf_release(account_ref.as(LibSecurity::CFTypeRef))

        return nil unless status == LibSecurity::ErrSecSuccess
        return nil if result.null?

        dict = result.as(LibSecurity::CFDictionaryRef)
        generic_ref = LibSecurity.cf_dictionary_get_value(dict, LibSecurity.kSecAttrGeneric.as(Void*))
        if generic_ref
          if bytes = CFHelper.cfdata_to_bytes(generic_ref.as(LibSecurity::CFDataRef))
            begin
              meta = Hash(String, String).from_json(String.new(bytes))
              LibSecurity.cf_release(result)
              return meta
            rescue
              # ignore parse errors
            end
          end
        end
        LibSecurity.cf_release(result)
        nil
      {% else %}
        nil
      {% end %}
    end

    def get_credential(service : String, username : String) : Credential?
      return unless password = get_password(service, username)
      cred = Credential.new(service, username, password)
      if meta = fetch_metadata(service, username)
        meta.each { |k, v| cred.add_metadata(k, v) }
      end
      cred
    end

    # List credentials - returns service/account pairs without passwords
    #
    # IMPORTANT LIMITATION: Due to macOS Keychain permission model, fetching passwords
    # for credentials created by other binaries triggers authorization dialogs.
    # This makes full credential listing impractical in non-interactive environments.
    #
    # WORKAROUND: This implementation returns credentials WITHOUT passwords to avoid dialogs.
    # Use get_password(service, account) to fetch specific passwords as needed.
    #
    # For tracking your own credentials, consider:
    # - Using a consistent service name prefix (e.g., "myapp:*")
    # - Maintaining an external credential index
    # - Using the search() method with known patterns
    def list_credentials : Array(Credential)
      {% if flag?(:darwin) %}
        credentials = [] of Credential

        # Query for all generic password attributes (without password data)
        query = CFHelper.create_mutable_dict

        CFHelper.dict_set(query, LibSecurity.kSecClass.as(Void*), LibSecurity.kSecClassGenericPassword.as(Void*))
        CFHelper.dict_set(query, LibSecurity.kSecMatchLimit.as(Void*), LibSecurity.kSecMatchLimitAll.as(Void*))
        CFHelper.dict_set(query, LibSecurity.kSecReturnAttributes.as(Void*), LibSecurity.kCFBooleanTrue.as(Void*))

        result = Pointer(Void).null.as(LibSecurity::CFTypeRef)
        status = LibSecurity.sec_item_copy_matching(query.as(LibSecurity::CFDictionaryRef), pointerof(result))

        LibSecurity.cf_release(query.as(LibSecurity::CFTypeRef))

        # Handle query results
        if status == LibSecurity::ErrSecItemNotFound
          return credentials
        elsif status != LibSecurity::ErrSecSuccess
          Log.warn { "list_credentials query failed with status: #{status}" }
          return credentials
        end

        if !result.null?
          # Parse CFArray of CFDictionary items
          array = result.as(LibSecurity::CFArrayRef)
          count = LibSecurity.cf_array_get_count(array)

          count.times do |i|
            dict = LibSecurity.cf_array_get_value_at_index(array, i.to_i64).as(LibSecurity::CFDictionaryRef)

            # Extract service and account from attributes
            service_ref = LibSecurity.cf_dictionary_get_value(dict, LibSecurity.kSecAttrService.as(Void*))
            service = service_ref ? CFHelper.cfstring_to_string(service_ref.as(LibSecurity::CFStringRef)) : nil

            account_ref = LibSecurity.cf_dictionary_get_value(dict, LibSecurity.kSecAttrAccount.as(Void*))
            account = account_ref ? CFHelper.cfstring_to_string(account_ref.as(LibSecurity::CFStringRef)) : nil

            # Create credential WITHOUT password (password=nil)
            # Users can call get_password(service, account) separately if needed
            if service && account
              credentials << Credential.new(service, account, nil)
            end
          end

          LibSecurity.cf_release(result)
        end

        credentials
      {% else %}
        [] of Credential
      {% end %}
    end
  end
end
