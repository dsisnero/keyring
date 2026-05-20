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

  {% if !LibC.has_constant?(:MAP_SHARED) %}
    lib LibC
      MAP_SHARED    = 0x01
      MAP_PRIVATE   = 0x02
      MAP_FIXED     = 0x10
      MAP_ANONYMOUS = 0x20
      MAP_ANON      = MAP_ANONYMOUS
      MAP_FAILED    = Pointer(Void).null
      MAP_DONTDUMP  = 0
      MAP_HUGETLB   = 0
      MAP_HUGE_1GB  = 0
      MAP_HUGE_2MB  = 0
      MS_SYNC       = 4
      MREMAP_MAYMOVE = 1
      SC_PAGESIZE   = 30
    end
  {% end %}
{% end %}
