@echo off
SETLOCAL
CD /D "%~dp0"

REM check admin
rem we need admin because we write to some previliged keys directly without virtlauncher
fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

mode con | findstr "32766" >nul|| mode con lines=32766 COLS=120 &REM prevent "mode con" from clearing the console


:: ============================================================
REM set VLAUNCHER_VERBOSE=true
set VLAUNCHER_DEBUG=true


:: ============================================================
cd /d "..\build"

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



@rem NOTE:writes to HKEY_CLASSES_ROOT go to %VIRT_ROOT%\HKEY_LOCAL_MACHINE\SOFTWARE\Classes and %VIRT_ROOT%\HKEY_USERS\S-1-5-21-3874345145-3142222481-512852731-1000_Classes not %VIRT_ROOT%\HKEY_CLASSES_ROOT
set "REAL_key=HKEY_CLASSES_ROOT\VirtTest_HKCR_Real"
set "VIRT_key=%VIRT_ROOT%\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\VirtTest_HKCR_Real"
call :run_tests

set "REAL_key=HKEY_USERS\%USER_SID%_Classes\VirtHookLeak"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

@rem NOTE:writes to HKEY_USERS\S-1-5-21-3874345145-3142222481-512852731-1000 go to %VIRT_ROOT%\HKEY_CURRENT_USER not %VIRT_ROOT%\S-1-5-21-3874345145-3142222481-512852731-1000
set "REAL_key=HKEY_USERS\%USER_SID%\VirtHookLeak"
set "VIRT_key=%VIRT_ROOT%\HKEY_CURRENT_USER\VirtHookLeak"
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



@rem ==========================================================================================

:run_tests
echo =============================================
echo  %REAL_key%
echo =============================================
echo.

:: Cleanup real host registry to ensure clean slate
call :CLEANUP

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
%LAUNCHER% -r "%VIRT_ROOT%" cmd /c reg query "%REAL_key%" /v WriteVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass
) else (
    call :Fail "Reg Delete: key still exists in Virtual Root."
)

echo ______Check if tombstone is created inside the virtual root
@rem value have a type of 0x1337DEAD by reg.exe return REG_NONE, when value exist it return REG_SZ
reg query "%VIRT_key%" /v WriteVal 2>nul | findstr /C:"WriteVal    REG_NONE" >nul 
if %ERRORLEVEL% NEQ 0 (
    call :Fail "Reg Delete: tombstone does not exist in Virtual Root."
) else (
    call :Pass
)


echo.
echo ====================== 3. merged view

echo ______Check if Value can be read from the Virtual world
%LAUNCHER% -r "%VIRT_ROOT%" -e cmd /c reg add "%REAL_key%" /v WriteVal /t REG_SZ /d SuccessWrite /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e cmd /c reg query "%REAL_key%" /v WriteVal | findstr "SuccessWrite" >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail "merged view: Value is not visible from the virtual world."
)

echo ______Check if Value read from virtual world come from real world or virtual world
%LAUNCHER% -r "%VIRT_ROOT%" -e cmd /c reg add "%REAL_key%" /v WriteVal /t REG_SZ /d virtualworld /f >nul
reg add "%REAL_key%" /v WriteVal /t REG_SZ /d realworld /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e cmd /c reg query "%REAL_key%" /v WriteVal | findstr "virtualworld" >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail "merged view: Value come from the real world."
)


echo ====================== 4. nested keys
echo ______Enumerate: check if virtual subkeys are enumerable via logical path
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_key%\SubA\SubB\SubC" /v Nested /t REG_SZ /d NestedVal /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_key%" 2>nul | findstr /i "SubA" >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass "7.5  Reg Enumerate: virtual subkeys enumerable via logical path"
) else (
    call :Fail "7.5  Reg Enumerate: virtual subkeys not visible under logical path"
)

echo ______case1
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_key%" /v xReadVal /t REG_SZ /d SuccessRead /f >nul 2>&1
%LAUNCHER% -r "%VIRT_ROOT%" -e reg add "%REAL_key%" /v zReadVal /t REG_SZ /d SuccessRead /f >nul 2>&1
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_key%" 2>nul | findstr /i "SubA" >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass "7.5  Reg Enumerate: virtual subkeys enumerable via logical path"
) else (
    call :Fail "7.5  Reg Enumerate: virtual subkeys not visible under logical path"
)

echo ______case2
%LAUNCHER% -r "%VIRT_ROOT%" -e reg delete "%REAL_key%" /v xReadVal /f >nul 2>&1
%LAUNCHER% -r "%VIRT_ROOT%" -e reg query "%REAL_key%" 2>nul | findstr /i "SubA" >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass "7.5  Reg Enumerate: virtual subkeys enumerable via logical path"
) else (
    call :Fail "7.5  Reg Enumerate: virtual subkeys not visible under logical path"
)


echo ______Check if deleted real key appear as removed inside the virtual root
@rem create nested keys in the real store
reg add "%REAL_key%\realSubA\realSubB\realSubC" /v realNested /t REG_SZ /d realNestedVal /f >nul

%LAUNCHER% -r "%VIRT_ROOT%" reg delete "%REAL_key%\realSubA" /f >nul

%LAUNCHER% -r "%VIRT_ROOT%" cmd /c reg query "%REAL_key%\realSubA" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass
) else (
    call :Fail "Reg Delete: key still exists in Virtual Root."
)

echo ______Check if tombstone is created inside the virtual root
@rem deleted keys have a value VL_KEY_DELETED with content type of 0x1337DEAD but reg.exe return REG_NONE, when value exist it return REG_SZ, so we check here for REG_NONE
reg query "%VIRT_key%\realSubA" /v VL_KEY_DELETED 2>nul | findstr /C:"VL_KEY_DELETED    REG_NONE" >nul 
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail "Reg Delete: tombstone does not exist in Virtual Root."
)

echo ______Check if the real nested non deleted keys inside a deleted key is not visible inside the virtual root
%LAUNCHER% -r "%VIRT_ROOT%" reg query "%REAL_key%\realSubA\realSubB\realSubC" /v realNested 2>nul | findstr "realNestedVal" >nul
if %ERRORLEVEL% EQU 0 (
    call :Fail "real nested non deleted keys inside a deleted key is visible inside the virtual root"
) else (
    call :Pass
)




call :CLEANUP
echo.
exit /b


@rem ==========================================================================================
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
