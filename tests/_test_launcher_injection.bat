@echo off
SETLOCAL
CD /D "%~dp0"

@rem dont use tasklist to list exe dll, it does not list all dll of x32 exe!! use listdlls


:: --- Configuration ---
set "TEST32_PATH=F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE32.exe"
set "TEST64_PATH=F:\_bin\_code\_kickstart\____shortcuts\_appz\_explorer\TablacusExplorer\_last\TE64.exe"
set "LISTDLLS_EXE=%~dp0ListDlls\listdlls64.exe"
set "BUILD_DIR=..\build"

@rem ___________________________________________________________
:: Extract exe name
for %%F in ("%TEST64_PATH%") do set "APP64_NAME=%%~nxF"
for %%F in ("%TEST32_PATH%") do set "APP32_NAME=%%~nxF"

:: Counters
set /a SUCCESS_COUNT=0
set /a FAIL_COUNT=0

if not exist "%BUILD_DIR%" (
    echo [ERROR] Build directory not found. Please build the project first.
    pause
    exit /b
)

cd "%BUILD_DIR%"

echo ============================================================
echo  VirtLauncher Injection Test Suite
echo ============================================================

:: 1. Initial Cleanup
echo [*] Cleaning up existing processes...
taskkill /f /im %APP32_NAME% /t >nul 2>&1
taskkill /f /im %APP64_NAME% /t >nul 2>&1
timeout /t 1 /nobreak >nul

:: --- Run Tests ---
echo ______________________________
:: x64 Launcher Tests
call :RunTest "x64 Launcher - x64 App (via cmd)" "VirtLauncher64.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini cmd /c %TEST64_PATH%" "VirtHook64.dll" "%APP64_NAME%"
echo ______________________________
call :RunTest "x64 Launcher - x64 App (Direct)"  "VirtLauncher64.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini %TEST64_PATH%" "VirtHook64.dll" "%APP64_NAME%"

echo ______________________________
:: x32 Launcher Tests
call :RunTest "x32 Launcher - x32 App (via cmd)" "VirtLauncher32.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini cmd /c %TEST32_PATH%" "VirtHook32.dll" "%APP32_NAME%"

echo ______________________________
call :RunTest "x32 Launcher - x32 App (Direct)"  "VirtLauncher32.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini %TEST32_PATH%" "VirtHook32.dll" "%APP32_NAME%"

echo ______________________________
:: Cross-Arch Tests
call :RunTest "x32 Launcher - x64 App (via cmd)" "VirtLauncher32.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini cmd /c %TEST64_PATH%" "VirtHook64.dll" "%APP64_NAME%"

echo ______________________________
call :RunTest "x32 Launcher - x64 App (Direct)"  "VirtLauncher32.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini %TEST64_PATH%" "VirtHook64.dll" "%APP64_NAME%"

echo ______________________________
call :RunTest "x64 Launcher - x32 App (via cmd)" "VirtLauncher64.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini cmd /c %TEST32_PATH%" "VirtHook32.dll" "%APP32_NAME%"
echo ______________________________
call :RunTest "x64 Launcher - x32 App (Direct)"  "VirtLauncher64.exe -reg HKEY_CURRENT_USER\VirtApp -fs redirects.ini %TEST32_PATH%" "VirtHook32.dll" "%APP32_NAME%"

:: --- Final Results ---
echo.
echo ============================================================
echo  TEST SUMMARY
echo ============================================================
echo  Total Success: %SUCCESS_COUNT%
echo  Total Failures: %FAIL_COUNT%
echo ============================================================

if %FAIL_COUNT% equ 0 (
    echo  ALL TESTS PASSED
    color 2F
) else (
    echo  SOME TESTS FAILED
    color 4F
)

echo.
pause
exit /b

:: -------------------------------------------------------------------------
:: Helper function: :RunTest "Description" "Command" "ExpectedDLL" "ProcessName"
:: -------------------------------------------------------------------------
:RunTest
echo.
echo [TEST] %~1
@rem echo [EXEC] %~2

:: Start the launcher in the background so we can check it
start "" /b %~2 >nul 2>&1

:: Wait a moment for the process to initialize and the DLL to load
timeout /t 3 /nobreak >nul

:: Use listdlls to check for the hook
"%LISTDLLS_EXE%" -nobanner "%~4" 2>nul | findstr /i "%~3" >nul

if %ERRORLEVEL% equ 0 (
    echo [RESULT] SUCCESS: %~3 is injected into %~4
    set /a SUCCESS_COUNT+=1
) else (
    echo [RESULT] FAILED: %~3 NOT detected in %~4
    set /a FAIL_COUNT+=1
)

:: Cleanup for next test
taskkill /f /im %~4 /t >nul 2>&1
timeout /t 1 /nobreak >nul
goto :eof