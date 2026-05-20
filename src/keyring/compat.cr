# Platform compatibility shims.
# Provides stub constants for POSIX APIs not available on Windows.

{% if flag?(:windows) %}
  lib LibC
    {% begin %}
      # Memory protection constants (mmap — POSIX-only, stubbed on Windows)
      PROT_NONE  = 0x0
      PROT_READ  = 0x1
      PROT_WRITE = 0x2
      PROT_EXEC  = 0x4

      # Memory mapping flags (mmap — POSIX-only, stubbed on Windows)
      MAP_SHARED    = 0x01
      MAP_PRIVATE   = 0x02
      MAP_FIXED     = 0x10
      MAP_ANONYMOUS = 0x20
      MAP_HUGETLB   = 0x40000
      MAP_HUGE_2MB  = 21 << 26
      MAP_FAILED = Pointer(Void).new(-1)
    {% end %}
  end
{% end %}
