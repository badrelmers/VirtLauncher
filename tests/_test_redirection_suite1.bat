@echo off
SETLOCAL EnableDelayedExpansion
CD /D "%~dp0"

REM check admin
fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )


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
set OUTSIDE_DIR=%TEST_DIR%\outside
set INI_FILE=%TEST_DIR%\redirects.ini

:: Clean and prep workspace
rmdir /s /q "%TEST_DIR%" 2>nul
mkdir "%SRC_DIR%"
mkdir "%DST_DIR%"
mkdir "%OUTSIDE_DIR%"

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
echo  Note: Symlink tests may require running as Administrator.
echo ============================================================

:: ============================================================
:: FILE SYSTEM REDIRECT TESTS
:: ============================================================
echo.
echo --- [ FS Redirect Tests: Core ] ---

:: 1. FS Write / Create
echo ___________________:: 1. FS Write / Create
echo @echo off > "%TEST_DIR%\payload_fs_write.bat"
echo echo VirtualContent ^> "%SRC_DIR%\file_write.txt" >> "%TEST_DIR%\payload_fs_write.bat"

%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_write.bat"
if exist "%DST_DIR%\file_write.txt" (
    if not exist "%SRC_DIR%\file_write.txt" (
        call :Pass "FS Write: File successfully created in destination without leaking."
    ) else (
        call :Fail "FS Write: File leaked into the source directory!"
    )
) else (
    call :Fail "FS Write: File was not created in the virtual destination."
)

:: 2. FS Read
echo ___________________:: 2. FS Read
echo HiddenContent > "%DST_DIR%\file_read.txt"
echo @echo off > "%TEST_DIR%\payload_fs_read.bat"
echo findstr "HiddenContent" "%SRC_DIR%\file_read.txt" ^>nul >> "%TEST_DIR%\payload_fs_read.bat"
echo exit /b %%ERRORLEVEL%% >> "%TEST_DIR%\payload_fs_read.bat"

%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_read.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "FS Read: App successfully read destination file via logical source path."
) else (
    call :Fail "FS Read: App failed to read virtualized file."
)

:: 3. FS Rename
echo ___________________:: 3. FS Rename
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
echo ___________________:: 4. FS Delete
echo DeleteMe > "%DST_DIR%\file_del.txt"
echo @echo off > "%TEST_DIR%\payload_fs_del.bat"
echo del "%SRC_DIR%\file_del.txt" >> "%TEST_DIR%\payload_fs_del.bat"

%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_del.bat"
if not exist "%DST_DIR%\file_del.txt" (
    call :Pass "FS Delete: File successfully deleted from virtual destination."
) else (
    call :Fail "FS Delete: File still exists in virtual destination."
)

echo.
echo --- [ FS Redirect Tests: Copy, Move, ^& Attributes ] ---

:: 5. FS Move
echo ___________________:: 5. FS Move
echo MoveMe > "%DST_DIR%\file_move_src.txt"
echo @echo off > "%TEST_DIR%\payload_fs_move.bat"
echo move "%SRC_DIR%\file_move_src.txt" "%SRC_DIR%\file_move_dst.txt" ^>nul >> "%TEST_DIR%\payload_fs_move.bat"
%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_move.bat"
if exist "%DST_DIR%\file_move_dst.txt" (
    if not exist "%DST_DIR%\file_move_src.txt" (
        call :Pass "FS Move: File successfully moved within virtual destination."
    ) else (
        call :Fail "FS Move: Source file not removed after move."
    )
) else (
    call :Fail "FS Move: Target file not found in virtual destination."
)

:: 6. FS Copy (From real unmapped directory to mapped directory)
echo ___________________:: 6. FS Copy (From real unmapped directory to mapped directory)
echo CopyMe > "%OUTSIDE_DIR%\file_copy_src.txt"
echo @echo off > "%TEST_DIR%\payload_fs_copy.bat"
echo copy "%OUTSIDE_DIR%\file_copy_src.txt" "%SRC_DIR%\file_copy_dst.txt" ^>nul >> "%TEST_DIR%\payload_fs_copy.bat"
%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_copy.bat"
if exist "%DST_DIR%\file_copy_dst.txt" (
    call :Pass "FS Copy: File successfully copied into virtual destination."
) else (
    call :Fail "FS Copy: File was not copied into virtual destination."
)

:: 7. FS Attributes (Hide file)
echo ___________________:: 7. FS Attributes (Hide file)
echo AttrTest > "%DST_DIR%\file_attr.txt"
echo @echo off > "%TEST_DIR%\payload_fs_attr.bat"
echo attrib +h "%SRC_DIR%\file_attr.txt" >> "%TEST_DIR%\payload_fs_attr.bat"
%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_attr.bat"
set ATTR_FOUND=0
for /f "tokens=*" %%A in ('dir /ah /b "%DST_DIR%\file_attr.txt" 2^>nul') do set ATTR_FOUND=1
if !ATTR_FOUND! EQU 1 (
    call :Pass "FS Attributes: Hidden attribute successfully applied to virtual file."
) else (
    call :Fail "FS Attributes: Failed to apply hidden attribute virtually."
)

echo.
echo --- [ FS Redirect Tests: Directories ] ---

:: 8. FS Mkdir
echo ___________________:: 8. FS Mkdir
echo @echo off > "%TEST_DIR%\payload_fs_mkdir.bat"
echo mkdir "%SRC_DIR%\dir_test" >> "%TEST_DIR%\payload_fs_mkdir.bat"
%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_mkdir.bat"
if exist "%DST_DIR%\dir_test\" (
    call :Pass "FS MkDir: Directory successfully created in virtual destination."
) else (
    call :Fail "FS MkDir: Directory not created in virtual destination."
)

:: 9. FS Rmdir
echo ___________________:: 9. FS Rmdir
mkdir "%DST_DIR%\dir_del"
echo @echo off > "%TEST_DIR%\payload_fs_rmdir.bat"
echo rmdir "%SRC_DIR%\dir_del" >> "%TEST_DIR%\payload_fs_rmdir.bat"
%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_rmdir.bat"
if not exist "%DST_DIR%\dir_del\" (
    call :Pass "FS RmDir: Directory successfully deleted from virtual destination."
) else (
    call :Fail "FS RmDir: Directory still exists in virtual destination."
)

echo.
echo --- [ FS Redirect Tests: Links, Junctions ^& Reparse Points ] ---

:: 10. Hard Link File (Write/Read)
echo ___________________:: 10. Hard Link File (Write/Read)
echo HLinkData > "%DST_DIR%\file_hlink_src.txt"
echo @echo off > "%TEST_DIR%\payload_fs_hlink.bat"
echo mklink /H "%SRC_DIR%\file_hlink_dst.txt" "%SRC_DIR%\file_hlink_src.txt" ^>nul >> "%TEST_DIR%\payload_fs_hlink.bat"
echo echo AppendedLink ^>^> "%SRC_DIR%\file_hlink_dst.txt" >> "%TEST_DIR%\payload_fs_hlink.bat"
%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_hlink.bat"
if exist "%DST_DIR%\file_hlink_dst.txt" (
    findstr "AppendedLink" "%DST_DIR%\file_hlink_src.txt" >nul
    if !ERRORLEVEL! EQU 0 (
        call :Pass "FS Hard Link: File hard linked and written to successfully in virtual store."
    ) else (
        call :Fail "FS Hard Link: Link created, but write did not propagate to target."
    )
) else (
    call :Fail "FS Hard Link: Target file not found in virtual destination."
)

:: 11. Symlink File (Write/Read)
echo ___________________:: 11. Symlink File (Write/Read)
echo SymlinkData > "%DST_DIR%\file_sym_src.txt"
echo @echo off > "%TEST_DIR%\payload_fs_sym.bat"
echo mklink "%SRC_DIR%\file_sym_dst.txt" "%SRC_DIR%\file_sym_src.txt" ^>nul >> "%TEST_DIR%\payload_fs_sym.bat"
echo echo AppendedSym ^>^> "%SRC_DIR%\file_sym_dst.txt" >> "%TEST_DIR%\payload_fs_sym.bat"
%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_sym.bat" >nul 2>&1
if exist "%DST_DIR%\file_sym_dst.txt" (
    findstr "AppendedSym" "%DST_DIR%\file_sym_src.txt" >nul
    if !ERRORLEVEL! EQU 0 (
        call :Pass "FS Symlink File: Symlink created and written to successfully in virtual store."
    ) else (
        call :Fail "FS Symlink File: Link created, but write did not propagate via reparse point."
    )
) else (
    call :Fail "FS Symlink File: Target symlink not found (Did you run as Admin?)."
)

:: 12. Symlink Directory (Write/Read)
echo ___________________:: 12. Symlink Directory (Write/Read)
mkdir "%DST_DIR%\dir_sym_src"
echo @echo off > "%TEST_DIR%\payload_fs_dir_sym.bat"
echo mklink /D "%SRC_DIR%\dir_sym_dst" "%SRC_DIR%\dir_sym_src" ^>nul >> "%TEST_DIR%\payload_fs_dir_sym.bat"
echo echo InSymDir ^> "%SRC_DIR%\dir_sym_dst\test.txt" >> "%TEST_DIR%\payload_fs_dir_sym.bat"
%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_dir_sym.bat" >nul 2>&1
if exist "%DST_DIR%\dir_sym_src\test.txt" (
    call :Pass "FS Symlink Dir: Directory symlink created and written to successfully."
) else (
    if not exist "%DST_DIR%\dir_sym_dst\" (
        call :Fail "FS Symlink Dir: Target symlink not found (Did you run as Admin?)."
    ) else (
        call :Fail "FS Symlink Dir: Link created, but virtual write landed outside target."
    )
)

:: 13. Junction Directory (Write/Read)
echo ___________________:: 13. Junction Directory (Write/Read)
mkdir "%DST_DIR%\dir_junc_src"
echo @echo off > "%TEST_DIR%\payload_fs_dir_junc.bat"
echo mklink /J "%SRC_DIR%\dir_junc_dst" "%SRC_DIR%\dir_junc_src" ^>nul >> "%TEST_DIR%\payload_fs_dir_junc.bat"
echo echo InJuncDir ^> "%SRC_DIR%\dir_junc_dst\test.txt" >> "%TEST_DIR%\payload_fs_dir_junc.bat"
%LAUNCHER% -fs "%INI_FILE%" cmd /c "%TEST_DIR%\payload_fs_dir_junc.bat"
if exist "%DST_DIR%\dir_junc_src\test.txt" (
    call :Pass "FS Junction Dir: Directory junction created and written to successfully."
) else (
    call :Fail "FS Junction Dir: Failed to resolve reparse point properly to virtual store."
)


:: ============================================================
:: REGISTRY REDIRECT TESTS
:: ============================================================
echo.
echo --- [ Registry Redirect Tests ] ---

:: 1. Reg Write
echo ___________________:: 1. Reg Write
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
echo ___________________:: 2. Reg Read
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
echo ___________________:: 3. Reg Delete
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