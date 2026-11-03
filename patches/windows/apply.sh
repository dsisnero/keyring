#!/usr/bin/env bash
# Apply Windows compatibility patches to shard dependencies.
#
# Run from the repository root (or via `make patch-windows`) after
# `shards install` on Windows.
set -euo pipefail

cd "$(dirname "$0")/../.."

# crypto-secret/sodium pull in mmap, whose POSIX bindings do not exist on
# Windows. Use the stub implementation instead.
cp patches/windows/mmap/mmap.cr lib/mmap/src/mmap/mmap.cr

# sodium's linker helper is a POSIX shell script; use the Windows equivalents.
cp patches/windows/sodium/lib_sodium.cr lib/sodium/src/sodium/lib_sodium.cr
cp patches/windows/sodium/pkg-libs.bat lib/sodium/build/pkg-libs.bat
cp patches/windows/sodium/env.bat lib/sodium/build/env.bat

# Crystal's Windows stdlib now declares these Win32 functions with different
# signatures than win32cr's generated bindings. The keyring backend does not
# use them, so remove the duplicate declarations.
threading=lib/win32cr/src/win32cr/system/threading.cr
memory=lib/win32cr/src/win32cr/system/memory.cr

sed -i \
  -e 's/^    fun CreateSemaphoreA/    # fun CreateSemaphoreA/' \
  -e 's/^    fun CreateSemaphoreW/    # fun CreateSemaphoreW/' \
  -e 's/^    fun RegisterWaitForSingleObject/    # fun RegisterWaitForSingleObject/' \
  "$threading"

sed -i \
  -e 's/^    fun MapViewOfFile(/    # fun MapViewOfFile(/' \
  -e 's/^    fun UnmapViewOfFile(/    # fun UnmapViewOfFile(/' \
  -e 's/^    fun CreateFileMappingA(/    # fun CreateFileMappingA(/' \
  "$memory"
