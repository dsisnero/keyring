# Platform compatibility shims.
# Provides stub constants for POSIX APIs not available on Windows.

{% if flag?(:windows) %}
  # Redefine only constants missing from Windows LibC
  {% if !LibC.has_constant?(:PROT_NONE) %}
    lib LibC
      PROT_NONE  = 0x0
      PROT_READ  = 0x1
      PROT_WRITE = 0x2
      PROT_EXEC  = 0x4
    end
  {% end %}
  {% if !LibC.has_constant?(:MAP_SHARED) %}
    lib LibC
      MAP_SHARED    = 0x01
      MAP_PRIVATE   = 0x02
      MAP_FIXED     = 0x10
      MAP_ANONYMOUS = 0x20
      MAP_FAILED    = Pointer(Void).null
    end
  {% end %}
{% end %}
