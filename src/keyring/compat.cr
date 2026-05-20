# Platform compatibility shims for Windows.
# Defines missing POSIX LibC types and constants used by sodium/mmap deps.

{% if flag?(:windows) %}
  lib LibC
    alias UInt64T = UInt64
    alias Int64T = Int64
    alias UInt32T = UInt32
    alias Int32T = Int32
  end
{% end %}
