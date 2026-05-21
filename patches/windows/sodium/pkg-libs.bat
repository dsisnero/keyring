@echo off
REM pkg-libs.bat — Windows equivalent of pkg-libs.sh
REM Outputs linker flags for libsodium.
REM The LIB environment variable should already include the vcpkg path (set in CI).
echo libsodium.lib
