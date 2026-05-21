@echo off
setlocal enabledelayedexpansion

REM pkg-libs.bat — Windows equivalent of pkg-libs.sh
REM Called by Crystal @[Link] at compile time to get libsodium linker flags.
REM First argument (%%1) is the sodium shard root directory.

if not "%~1"=="" cd /d "%~1"

REM Check if LIBSODIUM_INSTALL=0 (user wants system libsodium, e.g. from vcpkg)
if "%LIBSODIUM_INSTALL%"=="0" goto :find_vcpkg

REM Otherwise run the normal env check
call "%~dp0env.bat" 2>nul
if errorlevel 1 goto :find_system

:find_vcpkg
REM Try vcpkg-installed libsodium (GitHub Actions, CI)
REM Navigate from sodium\build\ to project root, then into vcpkg_installed
for %%i in ("%~dp0..\..\..\..") do set "PROJECT_ROOT=%%~fi"
if exist "!PROJECT_ROOT!\vcpkg_installed\x64-windows\lib\libsodium.lib" (
    echo /LIBPATH:"!PROJECT_ROOT!\vcpkg_installed\x64-windows\lib"
    echo libsodium.lib
    exit /b 0
)

REM Also try vcpkg_installed directly in current directory tree
for %%i in ("%~dp0..\..\..\..\vcpkg_installed") do set "VCPKG=%%~fi"
if exist "!VCPKG!\x64-windows\lib\libsodium.lib" (
    echo /LIBPATH:"!VCPKG!\x64-windows\lib"
    echo libsodium.lib
    exit /b 0
)

:find_system
REM Try to find libsodium via VCPKG_ROOT or common install locations
if defined VCPKG_ROOT (
    for %%i in ("%VCPKG_ROOT%\packages\libsodium_x64-windows\lib") do set "VCPKG_LIB=%%~fi"
    if exist "!VCPKG_LIB!\libsodium.lib" (
        echo /LIBPATH:"!VCPKG_LIB!"
        echo libsodium.lib
        exit /b 0
    )
)

REM Fallback: output just the library name (linker will search LIB paths)
echo libsodium.lib
exit /b 0
