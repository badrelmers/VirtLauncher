@echo off
setlocal EnableDelayedExpansion
CD /D "%~dp0"

REM check admin
rem we need admin because we write to some previliged keys directly without virtlauncher
fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )


:: ============================================================
REM set VLAUNCHER_VERBOSE=true
set VLAUNCHER_DEBUG=true


:: ============================================================
cd /d "..\build"
color 2F

:: =====================================================================
:: Configuration
:: =====================================================================
set "LAUNCHER=VirtLauncher64.exe"
set "VIRT_ROOT=HKCU\VirtTest_Root"

:: Real target keys for testing
set "REAL_HKCU=HKCU\Software\VirtTest_Real"
set "REAL_HKLM=HKLM\SOFTWARE\VirtTest_Real"

:: Virtual mapped paths (Aligned with your LogicalToVirtual routing!)
set "VIRT_HKCU=%VIRT_ROOT%\HKEY_CURRENT_USER\Software\VirtTest_Real"
set "VIRT_HKLM=%VIRT_ROOT%\HKEY_LOCAL_MACHINE\SOFTWARE\VirtTest_Real"

set "FAIL_COUNT=0"
set "PASS_COUNT=0"

echo =======================================================
echo VirtLauncher Registry Virtualization Test Suite
echo =======================================================
echo Detected User SID: %USER_SID%
echo.

:: =====================================================================
:: Cleanup Phase (Pre-flight)
:: =====================================================================
echo [INFO] Cleaning up previous test artifacts...
reg delete "%VIRT_ROOT%" /f >nul 2>&1
reg delete "%REAL_HKCU%" /f >nul 2>&1
reg delete "%REAL_HKLM%" /f >nul 2>&1

:: =====================================================================
:: TEST 1: Basic HKCU Write Isolation
:: =====================================================================
echo.
echo === TEST 1: HKCU Write Isolation ===
%LAUNCHER% -r %VIRT_ROOT% -e cmd /c reg add %REAL_HKCU%\Test1 /v Data /d "VirtWrite" /f >nul 2>&1

call :AssertKeyMissing "%REAL_HKCU%\Test1" "Real HKCU should not leak"
call :AssertKeyExists "%VIRT_HKCU%\Test1" "Virtual HKCU should capture write"

:: =====================================================================
:: TEST 2: Basic HKLM Write Isolation
:: =====================================================================
echo.
echo === TEST 2: HKLM Write Isolation ===
%LAUNCHER% -r %VIRT_ROOT% -e cmd /c reg add %REAL_HKLM%\Test2 /v Data /d "VirtWrite" /f >nul 2>&1

call :AssertKeyMissing "%REAL_HKLM%\Test2" "Real HKLM should not leak"
call :AssertKeyExists "%VIRT_HKLM%\Test2" "Virtual HKLM should capture write"


:: =====================================================================
:: TEST 3: Deep Nested Path Creation (HKLM)
:: =====================================================================
echo.
echo === TEST 3: Deep Nested Path Creation (HKLM) ===
%LAUNCHER% -r %VIRT_ROOT% -e cmd /c reg add %REAL_HKLM%\Test3\Deep\Nested\Key /v Data /d "DeepWrite" /f >nul 2>&1

call :AssertKeyMissing "%REAL_HKLM%\Test3" "Real HKLM tree should not leak"
call :AssertKeyExists "%VIRT_HKLM%\Test3\Deep\Nested\Key" "Virtual HKLM should build full tree"


:: =====================================================================
:: TEST 4: Copy-on-Write (Overriding existing real values)
:: =====================================================================
echo.
echo === TEST 4: Copy-on-Write (HKCU) ===
:: Setup: Create a real key first
reg add %REAL_HKCU%\Test4 /v Config /d "REAL_DATA" /f >nul 2>&1

:: Action: Overwrite from within sandbox
%LAUNCHER% -r %VIRT_ROOT% -e cmd /c reg add %REAL_HKCU%\Test4 /v Config /d "VIRT_DATA" /f >nul 2>&1

:: Verification
call :AssertValueEquals "%REAL_HKCU%\Test4" "Config" "REAL_DATA" "Real value must remain untouched"
call :AssertValueEquals "%VIRT_HKCU%\Test4" "Config" "VIRT_DATA" "Virtual value must reflect sandbox override"


:: =====================================================================
:: TEST 5: Passthrough Read
:: =====================================================================
echo.
echo === TEST 5: Passthrough Read (HKLM) ===
:: Setup: Create a real key
reg add %REAL_HKLM%\Test5 /v Config /d "PASSTHROUGH" /f >nul 2>&1
if exist sandbox_read.log del sandbox_read.log

:: Action: Read it from sandbox and pipe to a file on disk
%LAUNCHER% -r %VIRT_ROOT% -e cmd /c "reg query %REAL_HKLM%\Test5 /v Config | findstr PASSTHROUGH > sandbox_read.log"

:: Verification
for %%R in (sandbox_read.log) do if %%~zR GTR 0 (
    call :Pass "Sandbox successfully read real underlying key"
) else (
    call :Fail "Sandbox failed to read underlying real key"
)
if exist sandbox_read.log del sandbox_read.log


:: =====================================================================
:: TEST 6: Deletion Prevention (Protecting the physical registry)
:: =====================================================================
echo.
echo === TEST 6: Deletion Prevention (HKCU) ===
:: Setup: Create a real key
reg add %REAL_HKCU%\Test6 /v Target /d "DO_NOT_DELETE" /f >nul 2>&1

:: Action: Sandbox attempts to delete it
%LAUNCHER% -r %VIRT_ROOT% -e cmd /c reg delete %REAL_HKCU%\Test6 /f >nul 2>&1

:: Verification
call :AssertKeyExists "%REAL_HKCU%\Test6" "Sandbox must not delete real physical keys"


:: =====================================================================
:: TEST 7: Registry Tombstoning (Masking Deleted Real Keys)
:: =====================================================================
echo.
echo === TEST 7: Registry Tombstoning (Delete Real Key) ===
:: Setup: Create a real key
reg add "%REAL_HKCU%\Test7" /v Config /d "REAL_DATA" /f >nul 2>&1

:: Action: Sandbox attempts to delete the key
%LAUNCHER% -r "%VIRT_ROOT%" -e cmd /c reg delete "%REAL_HKCU%\Test7" /f >nul 2>&1

:: Verification: The sandbox should no longer see it (it should be tombstoned)
%LAUNCHER% -r "%VIRT_ROOT%" -e cmd /c reg query "%REAL_HKCU%\Test7" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    call :Pass "Sandbox view correctly hides deleted real key (Tombstone working)"
) else (
    call :Fail "Sandbox still sees real key after deletion (Missing Tombstone logic!)"
)


:: =====================================================================
:: TEST 8: NtQueryKey Metadata (Merged Counts)
:: =====================================================================
echo.
echo === TEST 8: NtQueryKey Metadata (Merged Counts) ===
:: Setup: Create real value, then virtual value
reg add "%REAL_HKCU%\Test8" /v RealVal /d "1" /f >nul 2>&1
%LAUNCHER% -r "%VIRT_ROOT%" -e cmd /c reg add "%REAL_HKCU%\Test8" /v VirtVal /d "2" /f >nul 2>&1

:: Action: PowerShell relies on NtQueryKey (KeyFullInformation) for .ValueCount
%LAUNCHER% -r "%VIRT_ROOT%" -e powershell -NoProfile -Command "(Get-Item 'HKCU:\Software\VirtTest_Real\Test8').ValueCount | Out-File -FilePath sandbox_count.log -Encoding ascii"

:: Verification
set /p VAL_COUNT=<sandbox_count.log
set VAL_COUNT=%VAL_COUNT: =%
if "%VAL_COUNT%"=="2" (
    call :Pass "NtQueryKey returned correct merged ValueCount (2)"
) else (
    call :Fail "NtQueryKey returned wrong ValueCount: %VAL_COUNT% (Expected 2. Virtual-only count bug!)"
)
if exist sandbox_count.log del sandbox_count.log


:: =====================================================================
:: Final Results
:: =====================================================================
echo.
echo =======================================================
echo TEST RUN COMPLETE
echo =======================================================
echo PASSED: %PASS_COUNT%
echo FAILED: %FAIL_COUNT%

if %FAIL_COUNT% EQU 0 (
    echo.
    echo [OK] Registry Virtualization is working as expected.
) else (
    color 4F
    echo.
    echo [WARNING] There are virtualization leaks or logical failures!
)

:: Post-flight cleanup
reg delete "%VIRT_ROOT%" /f >nul 2>&1
reg delete "%REAL_HKCU%" /f >nul 2>&1
reg delete "%REAL_HKLM%" /f >nul 2>&1

pause
exit /b %FAIL_COUNT%


:: =====================================================================
:: Helper Functions
:: =====================================================================

:AssertKeyExists
reg query "%~1" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    call :Pass "%~2"
) else (
    color 4F
    call :Fail "%~2 (Expected key to exist: %~1)"
)
exit /b

:AssertKeyMissing
reg query "%~1" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    call :Pass "%~2"
) else (
    color 4F
    call :Fail "%~2 (Key leaked/exists: %~1)"
)
exit /b

:AssertValueEquals
:: %1=Key, %2=ValueName, %3=ExpectedData, %4=Message
reg query "%~1" /v "%~2" 2>nul | findstr /C:"%~3" >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass "%~4"
) else (
    color 4F
    call :Fail "%~4 (Expected value '%~3' in %~1\%~2)"
)
exit /b

:Pass
echo  [PASS] %~1
set /a PASS_COUNT+=1
exit /b

:Fail
echo  [FAIL] %~1
set /a FAIL_COUNT+=1
exit /b