# Platform compatibility shims.
# Provides stub constants for POSIX APIs not available on Windows.
# These allow the mmap shard (transitive dep of sodium) to compile on Windows.

{% if flag?(:windows) %}
  {% if !LibC.has_constant?(:PROT_NONE) %}
    lib LibC
      PROT_NONE  = 0x0
      PROT_READ  = 0x1
      PROT_WRITE = 0x2
      PROT_EXEC  = 0x4
    end
  {% end %}

  {% if !LibC.has_constant?(:UInt64T) %}
    lib LibC
      alias UInt64T = UInt64
      alias Int64T = Int64
    end
  {% end %}

  {% if !LibC.has_constant?(:MAP_ANON) %}
    lib LibC
      MAP_ANON = 0x20
    end
  {% end %}

  {% if !LibC.has_constant?(:MAP_FAILED) %}
    lib LibC
      MAP_FAILED = Pointer(Void).null
    end
  {% end %}

  {% if !LibC.has_constant?(:MS_SYNC) %}
    lib LibC
      MS_SYNC = 4
    end
  {% end %}

  {% if !LibC.has_constant?(:MREMAP_MAYMOVE) %}
    lib LibC
      MREMAP_MAYMOVE = 1
    end
  {% end %}

  {% if !LibC.has_constant?(:SC_PAGESIZE) %}
    lib LibC
      SC_PAGESIZE = 30
    end
  {% end %}
{% end %}
