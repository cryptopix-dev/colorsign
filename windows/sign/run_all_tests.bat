@echo off
setlocal enabledelayedexpansion

:: ColorSign Test Runner for Windows - Simplified to match linux/mac approach
:: This script runs the basic verification test

:: Test results
set TOTAL_TESTS=0
set PASSED_TESTS=0
set FAILED_TESTS=0

:: Main script starts here
echo ========================================
echo ColorSign Verification Test
echo ========================================
echo.

:: Check if build directory exists
if not exist "build" (
    echo Build directory not found. Please run build_windows.bat first.
    exit /b 1
)

echo.
echo Running verification test...
echo ---------------------------

:: Run comprehensive test suite
echo Running comprehensive ColorSign test suite...

:: Test 1: Parameters
if exist "build\tests\test_parameters.exe" (
    echo Running Parameters Test...
    build\tests\test_parameters.exe
    if %errorlevel% equ 0 (
        echo PASSED
        set /a PASSED_TESTS+=1
    ) else (
        echo FAILED
        set /a FAILED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
)

:: Test 2: Key Generation
if exist "build\tests\test_keygen.exe" (
    echo Running Key Generation Test...
    build\tests\test_keygen.exe
    if %errorlevel% equ 0 (
        echo PASSED
        set /a PASSED_TESTS+=1
    ) else (
        echo FAILED
        set /a FAILED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
)

:: Test 3: Signing
if exist "build\tests\test_sign.exe" (
    echo Running Signing Test...
    build\tests\test_sign.exe
    if %errorlevel% equ 0 (
        echo PASSED
        set /a PASSED_TESTS+=1
    ) else (
        echo FAILED
        set /a FAILED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
)

:: Test 4: Verification
if exist "build\tests\test_verify.exe" (
    echo Running Verification Test...
    build\tests\test_verify.exe
    if %errorlevel% equ 0 (
        echo PASSED
        set /a PASSED_TESTS+=1
    ) else (
        echo FAILED
        set /a FAILED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
)

:: Test 5: Color Integration
if exist "build\tests\test_color_integration.exe" (
    echo Running Color Integration Test...
    build\tests\test_color_integration.exe
    if %errorlevel% equ 0 (
        echo PASSED
        set /a PASSED_TESTS+=1
    ) else (
        echo FAILED
        set /a FAILED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
)

:: Test 6: Integration
if exist "build\tests\test_integration.exe" (
    echo Running Integration Test...
    build\tests\test_integration.exe
    if %errorlevel% equ 0 (
        echo PASSED
        set /a PASSED_TESTS+=1
    ) else (
        echo FAILED
        set /a FAILED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
)

:: Test 7: KAT (Known Answer Tests)
if exist "build\tests\test_kat.exe" (
    echo Running KAT Test...
    build\tests\test_kat.exe
    if %errorlevel% equ 0 (
        echo PASSED
        set /a PASSED_TESTS+=1
    ) else (
        echo FAILED
        set /a FAILED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
)

:: Test 8: Stress Tests
if exist "build\tests\test_stress.exe" (
    echo Running Stress Test...
    build\tests\test_stress.exe
    if %errorlevel% equ 0 (
        echo PASSED
        set /a PASSED_TESTS+=1
    ) else (
        echo FAILED
        set /a FAILED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
)

:: Test 9: Security Utilities
if exist "build\tests\test_security_utils.exe" (
    echo Running Security Utilities Test...
    build\tests\test_security_utils.exe
    if %errorlevel% equ 0 (
        echo PASSED
        set /a PASSED_TESTS+=1
    ) else (
        echo FAILED
        set /a FAILED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
)

:: Test 10: Key Images
if exist "build\test_key_images.exe" (
    echo Running Key Images Test...
    build\test_key_images.exe
    if %errorlevel% equ 0 (
        echo PASSED
        set /a PASSED_TESTS+=1
    ) else (
        echo FAILED
        set /a FAILED_TESTS+=1
    )
    set /a TOTAL_TESTS+=1
)

:: Test 11: Main verification test
if exist "build\colorsign_test.exe" (
    echo Running Main Verification Test...
    build\colorsign_test.exe
    echo PASSED
    set /a PASSED_TESTS+=1
    set /a TOTAL_TESTS+=1
)

echo.
echo ========================================
echo Test Summary
echo ========================================
echo Total Tests: !TOTAL_TESTS!
echo Passed: !PASSED_TESTS!
echo Failed: !FAILED_TESTS!

if !FAILED_TESTS! equ 0 (
    echo All tests passed!
    exit /b 0
) else (
    echo Some tests failed!
    exit /b 1
)