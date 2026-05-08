@echo off
SETLOCAL EnableDelayedExpansion
CD /D "%~dp0"

:: Navigate to the build directory where VirtLauncher is compiled
if exist "..\build" (
    cd "..\build"
) else if exist "build" (
    cd "build"
) else (
    echo [ERROR] Build directory not found. Please compile the project first.
    pause
    exit /b 1
)

:: Auto-detect the launcher to use (prefer 64-bit if available)
set LAUNCHER=VirtLauncher64.exe
if not exist "%LAUNCHER%" set LAUNCHER=VirtLauncher32.exe
if not exist "%LAUNCHER%" (
    echo [ERROR] VirtLauncher executable not found in build folder.
    pause
    exit /b 1
)

:: Setup workspace variables
set TEST_DIR=%CD%\_test_workspace
set SRC_DIR=%TEST_DIR%\src
set DST_DIR=%TEST_DIR%\dst
set INI_FILE=%TEST_DIR%\redirects.ini

:: Clean and prep workspace
rmdir /s /q "%TEST_DIR%" 2>nul
mkdir "%SRC_DIR%"
mkdir "%DST_DIR%"

:: Create FS redirect config
echo %SRC_DIR%=%DST_DIR%> "%INI_FILE%"

:: Setup Registry workspace variables
set REG_VROOT=HKCU\VirtTest_Root
set REG_TARGET=HKCU\Software\VirtTest_App

:: Cleanup real host registry to ensure clean slate
reg delete "%REG_VROOT%" /f >nul 2>&1
reg delete "%REG_TARGET%" /f >nul 2>&1

set /a PASS_COUNT=0
set /a FAIL_COUNT=0

echo ============================================================
echo  VirtLauncher Redirection Test Suite
echo  Launcher: %LAUNCHER%
echo  Workspace: %TEST_DIR%
echo ============================================================

:: ============================================================
:: FILE SYSTEM REDIRECT TESTS
:: ============================================================
echo.
echo --- [ FS Redirect Tests ] ---

:: 1. FS Write / Create
echo @echo off > "%TEST_DIR%\payload_fs_write.bat"
echo echo VirtualContent ^> "%SRC_DIR%\file_write.txt" >> "%TEST_DIR%\payload_fs_write.bat"

%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_write.bat"

if exist "%DST_DIR%\file_write.txt" (
    if not exist "%SRC_DIR%\file_write.txt" (
        call :Pass "FS Write: File successfully created in destination without leaking to source."
    ) else (
        call :Fail "FS Write: File leaked into the source directory!"
    )
) else (
    call :Fail "FS Write: File was not created in the virtual destination."
)

:: 2. FS Read
echo HiddenContent > "%DST_DIR%\file_read.txt"
echo @echo off > "%TEST_DIR%\payload_fs_read.bat"
echo findstr "HiddenContent" "%SRC_DIR%\file_read.txt" ^>nul >> "%TEST_DIR%\payload_fs_read.bat"
echo exit /b %%ERRORLEVEL%% >> "%TEST_DIR%\payload_fs_read.bat"

%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_read.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "FS Read: App successfully read destination file using logical source path."
) else (
    call :Fail "FS Read: App failed to read virtualized file."
)

:: 3. FS Rename
echo RenameMe > "%DST_DIR%\file_ren.txt"
echo @echo off > "%TEST_DIR%\payload_fs_ren.bat"
echo rename "%SRC_DIR%\file_ren.txt" file_renamed.txt >> "%TEST_DIR%\payload_fs_ren.bat"

%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_ren.bat"
if exist "%DST_DIR%\file_renamed.txt" (
    call :Pass "FS Rename: File correctly renamed inside the virtual destination."
) else (
    call :Fail "FS Rename: File was not renamed in virtual destination."
)

:: 4. FS Delete
echo DeleteMe > "%DST_DIR%\file_del.txt"
echo @echo off > "%TEST_DIR%\payload_fs_del.bat"
echo del "%SRC_DIR%\file_del.txt" >> "%TEST_DIR%\payload_fs_del.bat"

%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_del.bat"
if not exist "%DST_DIR%\file_del.txt" (
    call :Pass "FS Delete: File successfully deleted from virtual destination."
) else (
    call :Fail "FS Delete: File still exists in virtual destination."
)


:: ============================================================
:: REGISTRY REDIRECT TESTS
:: ============================================================
echo.
echo --- [ Registry Redirect Tests ] ---

:: 1. Reg Write
echo @echo off > "%TEST_DIR%\payload_reg_write.bat"
echo reg add "%REG_TARGET%" /v WriteVal /t REG_SZ /d SuccessWrite /f ^>nul >> "%TEST_DIR%\payload_reg_write.bat"

%LAUNCHER% -reg "%REG_VROOT%" cmd /c "%TEST_DIR%\payload_reg_write.bat"

:: Check if it exists in the virtual root
reg query "%REG_VROOT%\Software\VirtTest_App" /v WriteVal 2>nul | findstr "SuccessWrite" >nul
if !ERRORLEVEL! EQU 0 (
    :: Check if it leaked to the real registry
    reg query "%REG_TARGET%" /v WriteVal >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        call :Fail "Reg Write: Key leaked into real logical host registry!"
    ) else (
        call :Pass "Reg Write: Key successfully written to Virtual Root without leaking."
    )
) else (
    call :Fail "Reg Write: Key not found in Virtual Root."
)

:: 2. Reg Read
:: Pre-populate the virtual root directly via host
reg add "%REG_VROOT%\Software\VirtTest_App" /v ReadVal /t REG_SZ /d SuccessRead /f >nul 2>&1

echo @echo off > "%TEST_DIR%\payload_reg_read.bat"
echo reg query "%REG_TARGET%" /v ReadVal 2^>nul ^| findstr "SuccessRead" ^>nul >> "%TEST_DIR%\payload_reg_read.bat"
echo exit /b %%ERRORLEVEL%% >> "%TEST_DIR%\payload_reg_read.bat"

%LAUNCHER% -reg "%REG_VROOT%" cmd /c "%TEST_DIR%\payload_reg_read.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "Reg Read: App successfully read Virtual Root key via logical path."
) else (
    call :Fail "Reg Read: App failed to read virtual registry key."
)

:: 3. Reg Delete
echo @echo off > "%TEST_DIR%\payload_reg_del.bat"
echo reg delete "%REG_TARGET%" /v ReadVal /f ^>nul 2^>^&1 >> "%TEST_DIR%\payload_reg_del.bat"

%LAUNCHER% -reg "%REG_VROOT%" cmd /c "%TEST_DIR%\payload_reg_del.bat"

:: Check if it's actually removed from virtual root
reg query "%REG_VROOT%\Software\VirtTest_App" /v ReadVal >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    call :Pass "Reg Delete: App successfully deleted key from Virtual Root."
) else (
    call :Fail "Reg Delete: Key still exists in Virtual Root."
)

:: ============================================================
:: CLEANUP & SUMMARY
:: ============================================================
echo.
echo [*] Cleaning up test artifacts...
reg delete "%REG_VROOT%" /f >nul 2>&1
reg delete "%REG_TARGET%" /f >nul 2>&1
rmdir /s /q "%TEST_DIR%" 2>nul

echo.
echo ============================================================
echo  TEST SUMMARY
echo ============================================================
echo  Passed : %PASS_COUNT%
echo  Failed : %FAIL_COUNT%
echo ============================================================

if %FAIL_COUNT% equ 0 (
    echo  [OK] ALL TESTS PASSED SUCCESSFULLY!
    color 2F
) else (
    echo  [X] SOME TESTS FAILED!
    color 4F
)

echo.
pause
exit /b %FAIL_COUNT%

:: -------------------------------------------------------------------------
:: Helpers
:: -------------------------------------------------------------------------
:Pass
echo   [+] PASS: %~1
set /a PASS_COUNT+=1
goto :eof

:Fail
echo   [-] FAIL: %~1
set /a FAIL_COUNT+=1
goto :eof