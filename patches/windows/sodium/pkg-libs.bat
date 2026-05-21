@echo off
setlocal enabledelayedexpansion

REM pkg-libs.bat — Windows equivalent of pkg-libs.sh
REM Outputs linker flags for libsodium (installed via vcpkg or system).
REM First argument (%%1) is the sodium shard root directory.

if not "%~1"=="" cd /d "%~1"

REM On GitHub Actions, GITHUB_WORKSPACE points to repo root
if defined GITHUB_WORKSPACE (
    if exist "%GITHUB_WORKSPACE%\vcpkg_installed\x64-windows\lib\libsodium.lib" (
        echo /LIBPATH:"%GITHUB_WORKSPACE%\vcpkg_installed\x64-windows\lib"
        echo libsodium.lib
        exit /b 0
    )
)

REM Try relative path from sodium/build/ up to project root
set "BAT_DIR=%~dp0"
REM BAT_DIR = <project>\lib\sodium\build\
REM Go up 4 levels to project root
for %%i in ("%BAT_DIR%..\..\..\..") do set "PROJECT_ROOT=%%~fi"
if exist "%PROJECT_ROOT%\vcpkg_installed\x64-windows\lib\libsodium.lib" (
    echo /LIBPATH:"%PROJECT_ROOT%\vcpkg_installed\x64-windows\lib"
    echo libsodium.lib
    exit /b 0
)

REM Try VCPKG_ROOT env var
if defined VCPKG_ROOT (
    for /d %%i in ("%VCPKG_ROOT%\installed\x64-windows\lib") do (
        if exist "%%i\libsodium.lib" (
            echo /LIBPATH:"%%i"
            echo libsodium.lib
            exit /b 0
        )
    )
)

REM Fallback: just the library name (linker searches LIB paths)
echo libsodium.lib
