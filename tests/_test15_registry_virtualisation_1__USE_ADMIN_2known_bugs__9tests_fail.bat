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



set "REAL_key=HKEY_LOCAL_MACHINE\SOFTWARE\Classes"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

set "REAL_key=HKEY_LOCAL_MACHINE\SOFTWARE"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

set "REAL_key=HKEY_CURRENT_USER\Software"
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

set "REAL_key=HKEY_USERS\.DEFAULT"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

set "REAL_key=HKEY_USERS\S-1-5-18"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

set "REAL_key=HKEY_USERS\S-1-5-19"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

set "REAL_key=HKEY_USERS\S-1-5-20"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

echo.
echo.
echo ##################################################
echo #************************************************#
echo #*                                              *#
echo #*  bugged ones                                 *#
echo #*                                              *#
echo #************************************************#
echo ##################################################
echo.
echo.

@rem NOTE:writes to HKEY_CLASSES_ROOT go to %VIRT_ROOT%\HKEY_LOCAL_MACHINE\SOFTWARE\Classes not %VIRT_ROOT%\HKEY_CLASSES_ROOT
set "REAL_key=HKEY_CLASSES_ROOT"
set "VIRT_key=%VIRT_ROOT%\HKEY_LOCAL_MACHINE\SOFTWARE\Classes"
call :run_tests

set "REAL_key=HKEY_USERS\%USER_SID%_Classes"
set "VIRT_key=%VIRT_ROOT%\%REAL_key%"
call :run_tests

@rem NOTE:writes to HKEY_USERS\S-1-5-21-3874345145-3142222481-512852731-1000 go to %VIRT_ROOT%\HKEY_CURRENT_USER not %VIRT_ROOT%\S-1-5-21-3874345145-3142222481-512852731-1000
set "REAL_key=HKEY_USERS\%USER_SID%"
set "VIRT_key=%VIRT_ROOT%\HKEY_CURRENT_USER"
call :run_tests


echo.
echo ============================================================
echo  TEST SUMMARY
echo ============================================================
echo  Passed : %PASS_COUNT%
echo  Failed : %FAIL_COUNT%
echo ============================================================

if %FAIL_COUNT% equ 0 (
    echo  [OK] ALL TESTS PASSED SUCCESSFULLY, this cannot happen
    color 2F
) else if %FAIL_COUNT% equ 9 (
    echo  [OK] 9 TESTS FAILED: this is expected
    color 5F
) else (
    echo  [X] this should not happen
    color 4F
)

echo.
echo.
echo ###########################################################################
echo #                                                                         #
echo #  9 tests should fail (because of 2 known unresolvable bugs):            #
echo #                                                                         #
echo #  this test show that some registry writes will leak to the real reg but it is not dangerous:
echo #    1 - writing a value in the root of HKEY_USERS\^<SID^>_Classes and HKEY_USERS\^<SID^> and HKEY_CLASSES_ROOT will be written to the real world not our virtual world
echo #    2 - and listing entries in the root of those 3 will list only real entries not merged ones so the virtual ones will not be visible but it s not bad too
echo #    this is not bad because nobody writes values in the root of those keys, usually apps write values inside a key inside those 3 keys so they will be virtualised because the bug happen only in the values written directly to the root of those 3 keys
echo #    this is all we can do when we hook in user space, to fix this 2 small problems we need to touch the kernel using a driver+signing...etc which i will not/dont want to do
echo #                                                                         #
echo ###########################################################################
echo.
echo.

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

echo ______Check if Value successfully written to Virtual Root
reg query "%VIRT_key%" /v WriteVal | findstr "SuccessWrite" >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail "Reg Write: Value not found in Virtual Root."
)

echo ______Check if Value leaked into real logical host registry
reg query "%REAL_key%" /v WriteVal >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Fail "Reg Write: Value leaked into real logical host registry"
) else (
    call :Pass
)

echo ______Check if we can read Virtual Root from the Virtual world
%LAUNCHER% -r "%VIRT_ROOT%" cmd /c reg query "%REAL_key%" /v WriteVal 2>nul | findstr "SuccessWrite" >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail "Reg Read: App failed to read virtual registry value."
)


echo.
echo ====================== 2. Reg Delete
%LAUNCHER% -r "%VIRT_ROOT%" cmd /c reg delete "%REAL_key%" /v WriteVal /f >nul

echo ______Check if value is removed from virtual root
reg query "%VIRT_key%" /v WriteVal >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass
) else (
    call :Fail "Reg Delete: Value still exists in Virtual Root."
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



echo ______Check if Value inside a new key can be read from the Virtual world
%LAUNCHER% -r "%VIRT_ROOT%" -e cmd /c reg add "%REAL_key%\virtleakkk" /v WriteVal /t REG_SZ /d SuccessWrite /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e cmd /c reg query "%REAL_key%\virtleakkk" /v WriteVal | findstr "SuccessWrite" >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail "merged view: Value inside the new key is not visible from the virtual world."
)

echo ______Check if Value inside a new key read from virtual world come from real world or virtual world
%LAUNCHER% -r "%VIRT_ROOT%" -e cmd /c reg add "%REAL_key%\virtleakkk" /v WriteVal /t REG_SZ /d virtualworld /f >nul
reg add "%REAL_key%\virtleakkk" /v WriteVal /t REG_SZ /d realworld /f >nul
%LAUNCHER% -r "%VIRT_ROOT%" -e cmd /c reg query "%REAL_key%\virtleakkk" /v WriteVal | findstr "virtualworld" >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass
) else (
    call :Fail "merged view: Value inside the new key come from the real world."
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
:: Crucial safety adjustment: deletes the temporary virtual sandbox root key safely, 
:: but on the host registry, it strictly deletes ONLY the test value (/v WriteVal) to safeguard core system hives.
reg delete "%VIRT_ROOT%" /f >nul 2>&1
reg delete "%REAL_key%" /v WriteVal /f >nul 2>&1
reg delete "%REAL_key%\virtleakkk" /f >nul 2>&1
exit /b
