@echo off
REM Build script for ColorSign Windows using batch commands

setlocal enabledelayedexpansion

echo ========================================
echo ColorSign Windows Build Script
echo ========================================
echo.

REM Check for required tools
echo Checking for required build tools...
set "requiredTools=cmake gcc openssl"
for %%t in (%requiredTools%) do (
    where %%t >nul 2>nul
    if !errorlevel! equ 0 (
        echo [OK] %%t found
    ) else (
        echo [ERROR] Required tool '%%t' is not installed or not in PATH.
        echo Please install it and ensure it's in your PATH.
        exit /b 1
    )
)

echo All required tools are available.
echo.

REM Set compiler environment variables for CMake
set "CC=C:/ProgramData/mingw64/mingw64/bin/gcc.exe"
set "CXX=C:/ProgramData/mingw64/mingw64/bin/g++.exe"
set "PATH=C:/ProgramData/mingw64/mingw64/bin;%PATH%"
set "PKG_CONFIG_EXECUTABLE=C:/msys64/usr/bin/pkg-config.exe"
set "PKG_CONFIG_PATH=C:/msys64/mingw64/lib/pkgconfig;%PKG_CONFIG_PATH%"
set "OPENSSL_ROOT_DIR=C:/ProgramData/mingw64/mingw64/opt"

REM Export environment variables for subprocesses
setx CC "C:/ProgramData/mingw64/mingw64/bin/gcc.exe"
setx CXX "C:/ProgramData/mingw64/mingw64/bin/g++.exe"

REM Clean build directory to avoid stale CMake cache issues
if exist "build" (
    echo Cleaning build directory...
    rmdir /s /q build
)

REM Create build directory
mkdir build

REM Change to build directory
cd build

REM Run CMake
echo Configuring project with CMake...
cmake .. -G "MinGW Makefiles" -DCMAKE_TOOLCHAIN_FILE="mingw-toolchain.cmake" -DPKG_CONFIG_EXECUTABLE="C:/msys64/usr/bin/pkg-config.exe"
if %errorlevel% neq 0 (
    echo CMake configuration failed.
    exit /b 1
)

REM Build the project
echo Building project...
cmake --build .
if %errorlevel% neq 0 (
    echo Build failed.
    exit /b 1
)

REM Return to original directory
cd ..

echo.
echo Build completed successfully!
echo Executables are available in the build/ directory:
echo   - colorsign_test: Main ColorSign test executable
echo   - ntt_simd_benchmark: NTT SIMD benchmark tool
echo.

REM Check if we can run the main test
if exist "build\colorsign_test.exe" (
    echo Running quick verification test...
    cd build
    colorsign_test.exe
    if %errorlevel% equ 0 (
        echo Verification test passed!
    ) else (
        echo Warning: Verification test failed.
    )
    cd ..
) else (
    echo Warning: colorsign_test.exe not found.
)

endlocal