@echo off
SETLOCAL
CD /D "%~dp0"

REM check admin
rem fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

:: ============================================================
REM set VLAUNCHER_VERBOSE=true
set VLAUNCHER_DEBUG=true


:: ============================================================
cd "..\build"

set LAUNCHER=VirtLauncher64.exe

:: Setup Registry workspace variables
set "VIRT_ROOT=HKEY_CURRENT_USER\VirtTest_Root"

set /a PASS_COUNT=0
set /a FAIL_COUNT=0


:: ============================================================
:: Main
:: ============================================================
echo ============================================================
echo  VirtLauncher Registry Redirection Test Suite
echo ============================================================
echo.

@rem NOTE:writes to HKEY_CLASSES_ROOT go to %VIRT_ROOT%\HKEY_LOCAL_MACHINE\SOFTWARE\Classes not %VIRT_ROOT%\HKEY_CLASSES_ROOT
set "REAL_key=HKEY_CLASSES_ROOT\VirtTest_HKCR_Real"
set "VIRT_key=%VIRT_ROOT%\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\VirtTest_HKCR_Real"
call :run_tests

set "REAL_key=HKEY_LOCAL_MACHINE\SOFTWARE\Classes\VirtTest_HKLM_Real"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

set "REAL_key=HKEY_LOCAL_MACHINE\SOFTWARE\VirtTest_HKLM_Real"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

set "REAL_key=HKEY_CURRENT_USER\Software\VirtTest_HKCU_Real"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests



:: 1. Automatically get the current user's SID
for /f "tokens=2 delims==" %%A in ('wmic useraccount where "name='%username%'" get sid /value 2^>nul') do (
    set "USER_SID=%%A"
)

:: Fallback method if WMIC is unavailable (common in newer Windows 11 builds)
if "%USER_SID%"=="" (
    for /f "tokens=2" %%A in ('whoami /user /fo table /nh') do (
        set "USER_SID=%%A"
    )
)

:: Trim any trailing spaces
set "USER_SID=%USER_SID: =%"

@rem echo [+] Found User SID: %USER_SID%


:: 2. Define the target key path and the test value

set "REAL_key=HKEY_USERS\%USER_SID%_Classes\VirtHookLeak"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

@rem NOTE:writes to HKEY_USERS\S-1-5-21-3874345145-3142222481-512852731-1000 go to %VIRT_ROOT%\HKEY_CURRENT_USER not %VIRT_ROOT%\S-1-5-21-3874345145-3142222481-512852731-1000
set "REAL_key=HKEY_USERS\%USER_SID%\VirtHookLeak"
set "VIRT_key=%VIRT_ROOT%\HKEY_CURRENT_USER\VirtHookLeak"
call :run_tests

set "REAL_key=HKEY_USERS\.DEFAULT\VirtHookLeak"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

set "REAL_key=HKEY_USERS\S-1-5-18\VirtHookLeak"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

set "REAL_key=HKEY_USERS\S-1-5-19\VirtHookLeak"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

set "REAL_key=HKEY_USERS\S-1-5-20\VirtHookLeak"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

echo.
echo ============================================================
echo  TEST SUMMARY
echo ============================================================
echo  Passed : %PASS_COUNT%
echo  Failed : %FAIL_COUNT%
echo ============================================================

if %FAIL_COUNT% equ 0 (
    echo  [OK] ALL TESTS PASSED SUCCESSFULLY
    color 2F
) else (
    echo  [X] SOME TESTS FAILED
    color 4F
)

call :CLEANUP
pause
exit /b


:: ============================================================
:: TESTS
:: ============================================================
:run_tests
:: Cleanup real host registry to ensure clean slate
call :CLEANUP

echo =============================================
echo  %REAL_key%
echo =============================================
echo.

echo ====================== 1. Reg Write/Read
%LAUNCHER% -r "%VIRT_ROOT%" -e cmd /c reg add "%REAL_key%" /v WriteVal /t REG_SZ /d SuccessWrite /f >nul

echo ______Check if Key successfully written to Virtual Root
reg query "%VIRT_key%" /v WriteVal | findstr "SuccessWrite" >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail "Reg Write: Key not found in Virtual Root."
)

echo ______Check if Key leaked into real logical host registry
reg query "%REAL_key%" /v WriteVal >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Fail "Reg Write: Key leaked into real logical host registry"
) else (
    call :Pass
)

echo ______Check if we can read Virtual Root from the Virtual world
%LAUNCHER% -r "%VIRT_ROOT%" cmd /c reg query "%REAL_key%" /v WriteVal 2>nul | findstr "SuccessWrite" >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail "Reg Read: App failed to read virtual registry key."
)


echo.
echo ====================== 2. Reg Delete
%LAUNCHER% -r "%VIRT_ROOT%" cmd /c reg delete "%REAL_key%" /v WriteVal /f >nul

echo ______Check if key is removed from virtual root
reg query "%VIRT_key%" /v WriteVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass
) else (
    call :Fail "Reg Delete: Key still exists in Virtual Root."
)


echo.
exit /b



:: -------------------------------------------------------------------------
:: Helpers
:: -------------------------------------------------------------------------
:Pass
rem echo good %~1
echo good
set /a PASS_COUNT+=1
goto :eof

:Fail
rem echo bad %~1
echo bad
set /a FAIL_COUNT+=1
goto :eof

:: ============================================================
:: CLEANUP & SUMMARY
:: ============================================================
:CLEANUP
echo.
rem echo [*] Cleaning up test artifacts...
reg delete "%VIRT_ROOT%" /f >nul 2>&1
reg delete "%REAL_key%" /f >nul 2>&1
exit /b
