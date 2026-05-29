@echo off
SETLOCAL EnableDelayedExpansion
CD /D "%~dp0"

REM check admin
fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

::_______________________________________________
REM set VLAUNCHER_VERBOSE=true
REM set VLAUNCHER_DEBUG=true


::_______________________________________________

:: ============================================================
::  VirtLauncher Comprehensive Redirection Test Suite  (v2)
::
::  Tests all virtualization hooks:
::    NtCreateFile / NtOpenFile
::    NtSetInformationFile  (FileRenameInformation, FileLinkInformation)
::    NtFsControlFile       (FSCTL_SET/GET_REPARSE_POINT  -- symlinks + junctions)
::    NtQueryAttributesFile (GetFileAttributes, attrib, if exist)
::    NtDeleteFile
::    CreateProcessW/A      (child process injection)
::    NtCreate/OpenKey, NtSetValueKey, etc. (registry)
:: ============================================================

cd "..\build"


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

:: Create FS redirect config: SRC -> DST
echo %SRC_DIR%=%DST_DIR%> "%INI_FILE%"

:: Setup Registry workspace variables
set VIRT_STORE=HKCU\VirtLauncher_redirection_suite2
set REG_TARGET=HKEY_CURRENT_USER\Software\VirtLauncher_redirection_suite2_test
set "REG_VROOT=%VIRT_STORE%\%REG_TARGET%"

:: Cleanup real host registry to ensure clean slate
reg delete "%VIRT_STORE%" /f >nul 2>&1
reg delete "%REG_TARGET%" /f >nul 2>&1

set /a PASS_COUNT=0
set /a FAIL_COUNT=0
set /a SKIP_COUNT=0

:: ---- Detect symlink privilege (requires admin or Developer Mode) ----
set SYMLINK_OK=0
echo symlink_priv_probe>"%TEST_DIR%\_sym_tgt_probe"
mklink "%TEST_DIR%\_sym_lnk_probe" "%TEST_DIR%\_sym_tgt_probe" >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    set SYMLINK_OK=1
    del "%TEST_DIR%\_sym_lnk_probe" 2>nul
)
del "%TEST_DIR%\_sym_tgt_probe" 2>nul

echo ============================================================
echo  VirtLauncher Comprehensive Redirection Test Suite  v2
echo  Launcher  : %LAUNCHER%
echo  Workspace : %TEST_DIR%
if %SYMLINK_OK% EQU 1 (
    echo  Symlinks  : ENABLED
) else (
    echo  Symlinks  : DISABLED  ^(run as Administrator or enable Developer Mode^)
)
echo ============================================================


:: ============================================================
:: SECTION 1 -- FS BASIC REDIRECT TESTS  (original four)
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 1]  FS Basic Redirect Tests
echo ============================================================

:: 1.1  Write / Create
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s1_write.bat"
echo echo VirtualContent^>"%SRC_DIR%\write.txt">>"%TEST_DIR%\pl_s1_write.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s1_write.bat"

if exist "%DST_DIR%\write.txt" (
    if not exist "%SRC_DIR%\write.txt" (
        call :Pass "1.1  FS Write: file created in dst, not leaked to src"
    ) else (
        call :Fail "1.1  FS Write: file leaked into src directory"
    )
) else (
    call :Fail "1.1  FS Write: file not created in dst"
)

:: 1.2  Read
echo ___________________
echo HiddenContent>"%DST_DIR%\read.txt"
echo @echo off>"%TEST_DIR%\pl_s1_read.bat"
echo findstr "HiddenContent" "%SRC_DIR%\read.txt" ^>nul>>"%TEST_DIR%\pl_s1_read.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s1_read.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s1_read.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "1.2  FS Read: dst file readable via logical src path"
) else (
    call :Fail "1.2  FS Read: failed to read virtualized file"
)

:: 1.3  Rename (within same directory)
echo ___________________
echo RenameMe>"%DST_DIR%\ren_orig.txt"
echo @echo off>"%TEST_DIR%\pl_s1_ren.bat"
echo rename "%SRC_DIR%\ren_orig.txt" ren_new.txt>>"%TEST_DIR%\pl_s1_ren.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s1_ren.bat"
if exist "%DST_DIR%\ren_new.txt" (
    call :Pass "1.3  FS Rename: file renamed inside dst"
) else (
    call :Fail "1.3  FS Rename: file not renamed in dst"
)

:: 1.4  Delete
echo ___________________
echo DeleteMe>"%DST_DIR%\del.txt"
echo @echo off>"%TEST_DIR%\pl_s1_del.bat"
echo del "%SRC_DIR%\del.txt">>"%TEST_DIR%\pl_s1_del.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s1_del.bat"
if not exist "%DST_DIR%\del.txt" (
    call :Pass "1.4  FS Delete: file deleted from dst"
) else (
    call :Fail "1.4  FS Delete: file still exists in dst"
)


:: ============================================================
:: SECTION 2 -- FS EXTENDED TESTS
::   Copy, cross-dir Move, Mkdir, if-exist check, dir listing,
::   Append write.
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 2]  FS Extended Tests
echo ============================================================

:: 2.1  Copy (NtCreateFile destination path translated)
echo ___________________
echo CopySource>"%DST_DIR%\copy_orig.txt"
echo @echo off>"%TEST_DIR%\pl_s2_copy.bat"
echo copy "%SRC_DIR%\copy_orig.txt" "%SRC_DIR%\copy_new.txt" ^>nul>>"%TEST_DIR%\pl_s2_copy.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s2_copy.bat"
if exist "%DST_DIR%\copy_new.txt" (
    if not exist "%SRC_DIR%\copy_new.txt" (
        call :Pass "2.1  FS Copy: copied file in dst, not leaked to src"
    ) else (
        call :Fail "2.1  FS Copy: copy leaked into src"
    )
) else (
    call :Fail "2.1  FS Copy: copy not found in dst"
)

:: 2.2  Move cross-directory (FileRenameInformation + translated dest path)
echo ___________________
mkdir "%DST_DIR%\subdir"
echo MoveContent>"%DST_DIR%\move_me.txt"
echo @echo off>"%TEST_DIR%\pl_s2_move.bat"
echo move "%SRC_DIR%\move_me.txt" "%SRC_DIR%\subdir\move_me.txt" ^>nul>>"%TEST_DIR%\pl_s2_move.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s2_move.bat"
if exist "%DST_DIR%\subdir\move_me.txt" (
    if not exist "%DST_DIR%\move_me.txt" (
        call :Pass "2.2  FS Move cross-dir: landed in dst\subdir, removed from dst root"
    ) else (
        call :Fail "2.2  FS Move cross-dir: original still in dst root after move"
    )
) else (
    call :Fail "2.2  FS Move cross-dir: file not found in dst\subdir"
)

:: 2.3  Subdirectory create (NtCreateFile with directory flag redirected)
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s2_mkdir.bat"
echo mkdir "%SRC_DIR%\newsubdir">>"%TEST_DIR%\pl_s2_mkdir.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s2_mkdir.bat"
if exist "%DST_DIR%\newsubdir\" (
    if not exist "%SRC_DIR%\newsubdir\" (
        call :Pass "2.3  FS Mkdir: directory created in dst, not src"
    ) else (
        call :Fail "2.3  FS Mkdir: directory leaked into src"
    )
) else (
    call :Fail "2.3  FS Mkdir: directory not created in dst"
)

:: 2.4  Existence check via if-exist (NtQueryAttributesFile redirected)
echo ___________________
echo ExistCheck>"%DST_DIR%\exist_check.txt"
echo @echo off>"%TEST_DIR%\pl_s2_exist.bat"
echo if exist "%SRC_DIR%\exist_check.txt" (exit /b 0) else (exit /b 1)>>"%TEST_DIR%\pl_s2_exist.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s2_exist.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "2.4  FS Exist check: dst file visible via src path (NtQueryAttributesFile)"
) else (
    call :Fail "2.4  FS Exist check: dst file not visible via src path"
)

:: 2.5  Directory listing (NtOpenFile on dir redirected; NtQueryDirectoryFileEx needs no hook)
echo ___________________
echo ListContent>"%DST_DIR%\listed.txt"
echo @echo off>"%TEST_DIR%\pl_s2_dir.bat"
echo dir "%SRC_DIR%" /b ^| findstr /i "listed.txt" ^>nul>>"%TEST_DIR%\pl_s2_dir.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s2_dir.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s2_dir.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "2.5  FS Dir listing: dst contents visible when enumerating src path"
) else (
    call :Fail "2.5  FS Dir listing: dst contents not visible via src path"
)

:: 2.6  Append write (opens existing dst file via src path and appends)
echo ___________________
echo LineOne>"%DST_DIR%\append.txt"
echo @echo off>"%TEST_DIR%\pl_s2_append.bat"
echo echo LineTwo^>^>"%SRC_DIR%\append.txt">>"%TEST_DIR%\pl_s2_append.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s2_append.bat"
findstr "LineTwo" "%DST_DIR%\append.txt" >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    call :Pass "2.6  FS Append write: appended content in dst file, not src"
) else (
    call :Fail "2.6  FS Append write: append did not land in dst file"
)


:: ============================================================
:: SECTION 3 -- FILE ATTRIBUTE TESTS
::   attrib uses NtQueryAttributesFile (read) + NtCreateFile
::   then NtSetInformationFile(FileBasicInformation) (write).
::   The file handle is already redirected by NtCreateFile, so
::   FileBasicInformation applies to the dst file with no extra
::   path translation needed.
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 3]  File Attribute Tests
echo ============================================================

:: 3.1  Set Hidden attribute -- verify on dst file from host
echo ___________________
echo AttrTest>"%DST_DIR%\attr_hidden.txt"
echo @echo off>"%TEST_DIR%\pl_s3_sethidden.bat"
echo attrib +H "%SRC_DIR%\attr_hidden.txt">>"%TEST_DIR%\pl_s3_sethidden.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s3_sethidden.bat"
attrib "%DST_DIR%\attr_hidden.txt" | findstr /R "H " >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    call :Pass "3.1  Set Hidden: H attribute applied to dst file"
) else (
    call :Fail "3.1  Set Hidden: H attribute NOT found on dst file"
)

:: 3.2  Read attributes via virtualized path
::      App queries attributes through src path; hook redirects to dst.
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s3_readhidden.bat"
echo attrib "%SRC_DIR%\attr_hidden.txt" ^| findstr /R "H " ^>nul>>"%TEST_DIR%\pl_s3_readhidden.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s3_readhidden.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s3_readhidden.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "3.2  Read Attributes: H attribute readable via src logical path"
) else (
    call :Fail "3.2  Read Attributes: H attribute not visible via src path"
)

:: 3.3  Set Read-Only attribute
echo ___________________
echo ReadOnlyTest>"%DST_DIR%\attr_ro.txt"
echo @echo off>"%TEST_DIR%\pl_s3_setro.bat"
echo attrib +R "%SRC_DIR%\attr_ro.txt">>"%TEST_DIR%\pl_s3_setro.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s3_setro.bat"
attrib "%DST_DIR%\attr_ro.txt" | findstr /R "R " >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    call :Pass "3.3  Set Read-Only: R attribute applied to dst file"
    attrib -R "%DST_DIR%\attr_ro.txt"
) else (
    call :Fail "3.3  Set Read-Only: R attribute NOT found on dst file"
)

:: 3.4  Clear attribute (remove Hidden via src path)
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s3_clrattr.bat"
echo attrib -H "%SRC_DIR%\attr_hidden.txt">>"%TEST_DIR%\pl_s3_clrattr.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s3_clrattr.bat"
attrib "%DST_DIR%\attr_hidden.txt" | findstr /R "H " >nul 2>&1
if !ERRORLEVEL! NEQ 0 (
    call :Pass "3.4  Clear Attribute: H attribute removed from dst file via src path"
) else (
    call :Fail "3.4  Clear Attribute: H attribute still set on dst file"
)



:: ============================================================
:: SECTION 4 -- HARD LINK TESTS
::   mklink /H calls NtSetInformationFile(FileLinkInformation).
::   The hook translates the link-target path from src to dst.
::
::   NOTE: NTFS does not support directory hard links; the kernel
::   rejects them with STATUS_ACCESS_DENIED regardless of any hook.
::   Hard link directory tests are therefore skipped by design.
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 4]  Hard Link Tests
echo ============================================================

:: 4.1  Hard link Write -- app creates hard link via src path; link lands in dst
echo ___________________
echo HardLinkOriginal>"%DST_DIR%\hl_orig.txt"
echo @echo off>"%TEST_DIR%\pl_s4_hlwrite.bat"
echo mklink /H "%SRC_DIR%\hl_link.txt" "%SRC_DIR%\hl_orig.txt">>"%TEST_DIR%\pl_s4_hlwrite.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s4_hlwrite.bat"
if exist "%DST_DIR%\hl_link.txt" (
    if not exist "%SRC_DIR%\hl_link.txt" (
        call :Pass "4.1  Hard Link File Write: link created in dst, not src"
    ) else (
        call :Fail "4.1  Hard Link File Write: link leaked into src"
    )
) else (
    call :Fail "4.1  Hard Link File Write: link not created in dst"
)

:: 4.2  Hard link Read -- pre-create hard link in dst, app reads via src logical path
echo ___________________
echo HardLinkReadContent>"%DST_DIR%\hl_read_orig.txt"
mklink /H "%DST_DIR%\hl_read_link.txt" "%DST_DIR%\hl_read_orig.txt" >nul 2>&1
if exist "%DST_DIR%\hl_read_link.txt" (
    echo @echo off>"%TEST_DIR%\pl_s4_hlread.bat"
    echo findstr "HardLinkReadContent" "%SRC_DIR%\hl_read_link.txt" ^>nul>>"%TEST_DIR%\pl_s4_hlread.bat"
    echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s4_hlread.bat"
    %LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s4_hlread.bat"
    if !ERRORLEVEL! EQU 0 (
        call :Pass "4.2  Hard Link File Read: content readable via src path"
    ) else (
        call :Fail "4.2  Hard Link File Read: failed to read through hard link via src path"
    )
) else (
    call :Fail "4.2  Hard Link File Read: setup failed -- could not create hard link in dst"
)

:: 4.3  Write via hard link propagates to original (hard links share one inode)
::      Both hl_prop_link and hl_prop_orig point to the same inode in dst.
::      Writing via the logical src\hl_prop_link path should be visible in dst\hl_prop_orig.
echo ___________________
echo OriginalContent>"%DST_DIR%\hl_prop_orig.txt"
mklink /H "%DST_DIR%\hl_prop_link.txt" "%DST_DIR%\hl_prop_orig.txt" >nul 2>&1
echo @echo off>"%TEST_DIR%\pl_s4_hlprop.bat"
echo echo ModifiedViaLink^>"%SRC_DIR%\hl_prop_link.txt">>"%TEST_DIR%\pl_s4_hlprop.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s4_hlprop.bat"
findstr "ModifiedViaLink" "%DST_DIR%\hl_prop_orig.txt" >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    call :Pass "4.3  Hard Link Propagation: write via src link path reflected in dst original"
) else (
    call :Fail "4.3  Hard Link Propagation: write via link not propagated to original"
)


:: ============================================================
:: SECTION 5 -- SYMLINK TESTS  (requires admin / Developer Mode)
::   mklink (no /D /J) -> FSCTL_SET_REPARSE_POINT (symlink tag 0xA000000C)
::   mklink /D           -> same, with directory flag
::   Hook translates absolute target path in reparse buffer on SET.
::   Hook reverse-translates on GET (path transparency).
::   Relative symlinks pass through unchanged -- they resolve relative
::   to the link's own directory which is already in dst.
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 5]  Symlink Tests
echo ============================================================

if %SYMLINK_OK% EQU 0 (
    call :Skip "5.1  Symlink File Write: no privilege (admin / Developer Mode required)"
    call :Skip "5.2  Symlink File Read: no privilege"
    call :Skip "5.3  Symlink File I/O through link: no privilege"
    call :Skip "5.4  Symlink Path Transparency (FSCTL_GET): no privilege"
    call :Skip "5.5  Symlink Dir Write: no privilege"
    call :Skip "5.6  Symlink Dir Read: no privilege"
    call :Skip "5.7  Symlink Dir I/O traversal: no privilege"
    goto :AfterSymlinkTests
)

:: 5.1  Symlink File Write
::      App creates symlink via src path; the hook translates src\target -> dst\target
::      in the reparse buffer (FSCTL_SET_REPARSE_POINT), and creates the link in dst.
echo ___________________
echo SymlinkTarget>"%DST_DIR%\sym_tgt.txt"
echo @echo off>"%TEST_DIR%\pl_s5_symwrite.bat"
echo mklink "%SRC_DIR%\sym_link.txt" "%SRC_DIR%\sym_tgt.txt">>"%TEST_DIR%\pl_s5_symwrite.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s5_symwrite.bat"
if exist "%DST_DIR%\sym_link.txt" (
    if not exist "%SRC_DIR%\sym_link.txt" (
        call :Pass "5.1  Symlink File Write: symlink created in dst, not src"
    ) else (
        call :Fail "5.1  Symlink File Write: symlink leaked into src"
    )
) else (
    call :Fail "5.1  Symlink File Write: symlink not created in dst"
)

:: 5.2  Symlink File Read
::      Pre-create symlink in dst (host-side); app opens via src path and reads through it.
echo ___________________
echo SymReadTarget>"%DST_DIR%\sym_read_tgt.txt"
mklink "%DST_DIR%\sym_read_lnk.txt" "%DST_DIR%\sym_read_tgt.txt" >nul 2>&1
echo @echo off>"%TEST_DIR%\pl_s5_symread.bat"
echo findstr "SymReadTarget" "%SRC_DIR%\sym_read_lnk.txt" ^>nul>>"%TEST_DIR%\pl_s5_symread.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s5_symread.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s5_symread.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "5.2  Symlink File Read: target content readable via src\symlink path"
) else (
    call :Fail "5.2  Symlink File Read: failed to read through symlink via src path"
)

:: 5.3  Symlink File I/O through app-created link
::      Link was created in 5.1 (dst\sym_link.txt -> dst\sym_tgt.txt).
::      App reads via src\sym_link.txt -> hook opens dst\sym_link.txt ->
::      kernel follows symlink to dst\sym_tgt.txt -> success.
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s5_symlinkio.bat"
echo findstr "SymlinkTarget" "%SRC_DIR%\sym_link.txt" ^>nul>>"%TEST_DIR%\pl_s5_symlinkio.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s5_symlinkio.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s5_symlinkio.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "5.3  Symlink File I/O: read via app-created symlink at src path works"
) else (
    call :Fail "5.3  Symlink File I/O: read via app-created symlink failed"
)

:: 5.4  Symlink Path Transparency (FSCTL_GET_REPARSE_POINT hook)
::      "fsutil reparsepoint query" outputs UTF-16LE which findstr on a redirected file cannot parse
::      reliably.  Instead we run "dir /AL" inside VirtLauncher and check whether
::      the printed link target contains the src path component (not dst).
::      "dir /AL" prints the reparse target using the path the process sees, so
::      if the GET hook is working the target will show src\, not dst\.
::
::      We capture to a plain-ASCII temp file by piping through "more" which
::      converts the dir output to the current OEM code page (ASCII-safe).
echo ___________________
set RPARSE_TMP=%TEMP%\vl_rparse_%RANDOM%.txt
echo @echo off>"%TEST_DIR%\pl_s5_sympath.bat"
rem echo dir /AL "%SRC_DIR%" 2^>nul ^| more ^>"%RPARSE_TMP%">>"%TEST_DIR%\pl_s5_sympath.bat"
echo dir /AL "%SRC_DIR%" 2^>nul ^>"%RPARSE_TMP%">>"%TEST_DIR%\pl_s5_sympath.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s5_sympath.bat"
if exist "%RPARSE_TMP%" (
    :: The dir /AL output prints  [target_path]  after the link name.
    :: Look for the src directory token in the output.  We search for the
    :: leaf name of SRC_DIR (guaranteed ASCII) so we don't depend on full path.
    for %%I in ("%SRC_DIR%") do set SRC_LEAF=%%~nxI
    findstr /I /C:"!SRC_LEAF!" "%RPARSE_TMP%" >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        :: Also make sure dst leaf is absent from the link target field
        for %%I in ("%DST_DIR%") do set DST_LEAF=%%~nxI
        findstr /I /C:"!DST_LEAF!" "%RPARSE_TMP%" >nul 2>&1
        if !ERRORLEVEL! EQU 0 (
            call :Fail "5.4  Symlink Path Transparency: app sees physical dst path in reparse data"
        ) else (
            call :Pass "5.4  Symlink Path Transparency: FSCTL_GET returns logical src path to app"
        )
    ) else (
        call :Fail "5.4  Symlink Path Transparency: src path not found in dir /AL output (hook missing or no symlinks in src)"
    )
    del "%RPARSE_TMP%" 2>nul
) else (
    call :Fail "5.4  Symlink Path Transparency: dir /AL output file not created"
)

:: 5.5  Symlink Dir Write
echo ___________________
mkdir "%DST_DIR%\sym_real_dir"
echo @echo off>"%TEST_DIR%\pl_s5_symdirwrite.bat"
echo mklink /D "%SRC_DIR%\sym_link_dir" "%SRC_DIR%\sym_real_dir">>"%TEST_DIR%\pl_s5_symdirwrite.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s5_symdirwrite.bat"
if exist "%DST_DIR%\sym_link_dir" (
    if not exist "%SRC_DIR%\sym_link_dir" (
        call :Pass "5.5  Symlink Dir Write: dir symlink created in dst, not src"
    ) else (
        call :Fail "5.5  Symlink Dir Write: dir symlink leaked into src"
    )
) else (
    call :Fail "5.5  Symlink Dir Write: dir symlink not created in dst"
)

:: 5.6  Symlink Dir Read
::      Pre-create dir symlink in dst; app checks existence via src path.
echo ___________________
mkdir "%DST_DIR%\sym_rd_real_dir"
echo SymDirFile>"%DST_DIR%\sym_rd_real_dir\content.txt"
mklink /D "%DST_DIR%\sym_rd_link_dir" "%DST_DIR%\sym_rd_real_dir" >nul 2>&1
echo @echo off>"%TEST_DIR%\pl_s5_symdirread.bat"
echo if exist "%SRC_DIR%\sym_rd_link_dir" (exit /b 0) else (exit /b 1)>>"%TEST_DIR%\pl_s5_symdirread.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s5_symdirread.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "5.6  Symlink Dir Read: dir symlink visible via src path"
) else (
    call :Fail "5.6  Symlink Dir Read: dir symlink not visible via src path"
)

:: 5.7  Symlink Dir I/O traversal
::      Open dir handle via src\sym_rd_link_dir -> hook opens dst\sym_rd_link_dir ->
::      kernel follows the dir symlink -> reaches dst\sym_rd_real_dir -> reads content.
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s5_symdirtraverse.bat"
echo dir "%SRC_DIR%\sym_rd_link_dir" /b ^| findstr /i "content.txt" ^>nul>>"%TEST_DIR%\pl_s5_symdirtraverse.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s5_symdirtraverse.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s5_symdirtraverse.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "5.7  Symlink Dir I/O: file accessible through dir symlink via src path"
) else (
    call :Fail "5.7  Symlink Dir I/O: cannot traverse dir symlink via src path"
)

:AfterSymlinkTests


:: ============================================================
:: SECTION 6 -- JUNCTION TESTS  (no admin required)
::   mklink /J -> FSCTL_SET_REPARSE_POINT (mount-point tag 0xA0000003)
::   Hook translates absolute target path in reparse buffer on SET.
::   Hook reverse-translates on GET (path transparency).
::   NTFS mandates a null separator between SubstituteName and PrintName
::   in the reparse buffer -- the hook rebuilds the buffer correctly.
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 6]  Junction Tests
echo ============================================================

:: 6.1  Junction Write -- app creates junction via src path; lands in dst
echo ___________________
mkdir "%DST_DIR%\junc_real_dir"
echo @echo off>"%TEST_DIR%\pl_s6_juncwrite.bat"
echo mklink /J "%SRC_DIR%\junc_link" "%SRC_DIR%\junc_real_dir">>"%TEST_DIR%\pl_s6_juncwrite.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s6_juncwrite.bat"
if exist "%DST_DIR%\junc_link" (
    if not exist "%SRC_DIR%\junc_link" (
        call :Pass "6.1  Junction Write: junction created in dst, not src"
    ) else (
        call :Fail "6.1  Junction Write: junction leaked into src"
    )
) else (
    call :Fail "6.1  Junction Write: junction not created in dst"
)

:: 6.2  Junction Read -- pre-create junction in dst; app checks existence via src path
echo ___________________
mkdir "%DST_DIR%\junc_rd_real"
echo JuncContent>"%DST_DIR%\junc_rd_real\file.txt"
mklink /J "%DST_DIR%\junc_rd_link" "%DST_DIR%\junc_rd_real" >nul 2>&1
echo @echo off>"%TEST_DIR%\pl_s6_juncread.bat"
echo if exist "%SRC_DIR%\junc_rd_link" (exit /b 0) else (exit /b 1)>>"%TEST_DIR%\pl_s6_juncread.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s6_juncread.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "6.2  Junction Read: junction visible via src logical path"
) else (
    call :Fail "6.2  Junction Read: junction not visible via src path"
)

:: 6.3  Junction I/O traversal -- read file through junction via src path
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s6_juncio.bat"
echo findstr "JuncContent" "%SRC_DIR%\junc_rd_link\file.txt" ^>nul>>"%TEST_DIR%\pl_s6_juncio.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s6_juncio.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s6_juncio.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "6.3  Junction I/O: file readable through junction via src path"
) else (
    call :Fail "6.3  Junction I/O: cannot read file through junction via src path"
)

:: 6.4  Junction Path Transparency (FSCTL_GET_REPARSE_POINT hook)
::      Same UTF-16LE problem as 5.4: use "dir /AL" piped through "more" to get
::      an ASCII-safe listing.  The junction target printed by dir should show the
::      logical src path (after reverse-translation by the hook), not the physical
::      dst path.
echo ___________________
set JRPARSE_TMP=%TEMP%\vl_jrparse_%RANDOM%.txt
echo @echo off>"%TEST_DIR%\pl_s6_juncpath.bat"
rem echo dir /AL "%SRC_DIR%" 2^>nul ^| more ^>"%JRPARSE_TMP%">>"%TEST_DIR%\pl_s6_juncpath.bat"
echo dir /AL "%SRC_DIR%" 2^>nul ^>"%JRPARSE_TMP%">>"%TEST_DIR%\pl_s6_juncpath.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s6_juncpath.bat"
if exist "%JRPARSE_TMP%" (
    for %%I in ("%SRC_DIR%") do set SRC_LEAF=%%~nxI
    findstr /I /C:"!SRC_LEAF!" "%JRPARSE_TMP%" >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        for %%I in ("%DST_DIR%") do set DST_LEAF=%%~nxI
        findstr /I /C:"!DST_LEAF!" "%JRPARSE_TMP%" >nul 2>&1
        if !ERRORLEVEL! EQU 0 (
            call :Fail "6.4  Junction Path Transparency: app sees physical dst path in reparse data"
        ) else (
            call :Pass "6.4  Junction Path Transparency: FSCTL_GET returns logical src path to app"
        )
    ) else (
        call :Fail "6.4  Junction Path Transparency: src path not found in dir /AL output (hook missing or no junctions in src)"
    )
    del "%JRPARSE_TMP%" 2>nul
) else (
    call :Fail "6.4  Junction Path Transparency: dir /AL output file not created"
)

:: 6.5  Write file into junction target via src junction path
::      Open file handle via src\junc_link\new.txt ->
::        hook translates to dst\junc_link\new.txt ->
::        kernel resolves junction -> dst\junc_rd_real\new.txt.
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s6_juncwrfile.bat"
echo echo ViaJunction^>"%SRC_DIR%\junc_rd_link\new.txt">>"%TEST_DIR%\pl_s6_juncwrfile.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s6_juncwrfile.bat"
if exist "%DST_DIR%\junc_rd_real\new.txt" (
    call :Pass "6.5  Junction Write Through: file written via junction landed in real target dir"
) else (
    call :Fail "6.5  Junction Write Through: file not found in real target dir after write via junction"
)


:: ============================================================
:: SECTION 7 -- REGISTRY TESTS  (basic + extended)
::
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 7]  Registry Tests
echo ============================================================

:: 7.1  Reg Write (no leak to real host registry)
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s7_regwrite.bat"
echo reg add "%REG_TARGET%" /v WriteVal /t REG_SZ /d SuccessWrite /f ^>nul>>"%TEST_DIR%\pl_s7_regwrite.bat"

%LAUNCHER% -r "%VIRT_STORE%" cmd /c "%TEST_DIR%\pl_s7_regwrite.bat"

reg query "%REG_VROOT%" /v WriteVal 2>nul | findstr "SuccessWrite" >nul
if !ERRORLEVEL! EQU 0 (
    reg query "%REG_TARGET%" /v WriteVal >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        call :Fail "7.1  Reg Write: key leaked into real host registry"
    ) else (
        call :Pass "7.1  Reg Write: key in virtual root, no leak to host registry"
    )
) else (
    call :Fail "7.1  Reg Write: key not found in virtual root"
)

:: 7.2  Reg Read
echo ___________________
reg add "%REG_VROOT%" /v ReadVal /t REG_SZ /d SuccessRead /f >nul 2>&1
echo @echo off>"%TEST_DIR%\pl_s7_regread.bat"
echo reg query "%REG_TARGET%" /v ReadVal 2^>nul ^| findstr "SuccessRead" ^>nul>>"%TEST_DIR%\pl_s7_regread.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s7_regread.bat"

%LAUNCHER% -r "%VIRT_STORE%" cmd /c "%TEST_DIR%\pl_s7_regread.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "7.2  Reg Read: virtual key readable via logical host path"
) else (
    call :Fail "7.2  Reg Read: failed to read virtual key via logical path"
)

:: 7.3  Reg Delete value
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s7_regdel.bat"
echo reg delete "%REG_TARGET%" /v ReadVal /f ^>nul 2^>^&1 >>"%TEST_DIR%\pl_s7_regdel.bat"

%LAUNCHER% -r "%VIRT_STORE%" cmd /c "%TEST_DIR%\pl_s7_regdel.bat"

%LAUNCHER% -r "%VIRT_STORE%" cmd /c reg query "%REG_TARGET%" /v ReadVal >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    call :Pass "7.3  Reg Delete Value: value deleted from virtual root"
) else (
    call :Fail "7.3  Reg Delete Value: value still exists in virtual root"
)

:: 7.4  Reg Create deeply nested subkey
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s7_regsub.bat"
echo reg add "%REG_TARGET%\SubA\SubB\SubC" /v Nested /t REG_SZ /d NestedVal /f ^>nul>>"%TEST_DIR%\pl_s7_regsub.bat"

%LAUNCHER% -r "%VIRT_STORE%" cmd /c "%TEST_DIR%\pl_s7_regsub.bat"
reg query "%REG_VROOT%\SubA\SubB\SubC" /v Nested 2>nul | findstr "NestedVal" >nul
if !ERRORLEVEL! EQU 0 (
    call :Pass "7.4  Reg Nested Subkey: 3-level deep key created in virtual root"
) else (
    call :Fail "7.4  Reg Nested Subkey: nested key not found in virtual root"
)

:: 7.5  Reg Enumerate subkeys (NtEnumerateKey must enumerate virtual subkeys)
echo ___________________
%LAUNCHER% -r "%VIRT_STORE%" cmd /c reg query "%REG_TARGET%" 2>nul | findstr /i "SubA" >nul
if !ERRORLEVEL! EQU 0 (
    call :Pass "7.5  Reg Enumerate: virtual subkeys enumerable via logical path"
) else (
    call :Fail "7.5  Reg Enumerate: virtual subkeys not visible under logical path"
)

:: 7.6  Reg DWORD write and read back
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s7_regdword.bat"
echo reg add "%REG_TARGET%" /v DwordVal /t REG_DWORD /d 0x1234 /f ^>nul>>"%TEST_DIR%\pl_s7_regdword.bat"
echo reg query "%REG_TARGET%" /v DwordVal 2^>nul ^| findstr "0x1234" ^>nul>>"%TEST_DIR%\pl_s7_regdword.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s7_regdword.bat"

%LAUNCHER% -r "%VIRT_STORE%" cmd /c "%TEST_DIR%\pl_s7_regdword.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "7.6  Reg DWORD: DWORD written and read back correctly via virtual path"
) else (
    call :Fail "7.6  Reg DWORD: DWORD write/read failed via virtual path"
)

:: 7.7  Reg write multiple values; verify all enumerable in same virtual key
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s7_regmulti.bat"
echo reg add "%REG_TARGET%" /v ValA /t REG_SZ /d AAA /f ^>nul>>"%TEST_DIR%\pl_s7_regmulti.bat"
echo reg add "%REG_TARGET%" /v ValB /t REG_SZ /d BBB /f ^>nul>>"%TEST_DIR%\pl_s7_regmulti.bat"
echo reg add "%REG_TARGET%" /v ValC /t REG_SZ /d CCC /f ^>nul>>"%TEST_DIR%\pl_s7_regmulti.bat"
echo reg query "%REG_TARGET%" 2^>nul ^| findstr "ValC" ^>nul>>"%TEST_DIR%\pl_s7_regmulti.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s7_regmulti.bat"

%LAUNCHER% -r "%VIRT_STORE%" cmd /c "%TEST_DIR%\pl_s7_regmulti.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "7.7  Reg Multi-value: multiple values all enumerable in virtual key"
) else (
    call :Fail "7.7  Reg Multi-value: not all values visible in virtual key"
)

:: 7.8  Reg Delete entire subkey tree (reg delete /f on a subkey with children)
::      BUG: Hook_NtDeleteKey deletes hVirt, but the CoW model re-creates hVirt
::      from hReal the next time the key is opened.  Requires tombstone tracking
::      in DoVirtOpen to prevent CoW-resurrecting a deleted virtual subtree.
echo ___________________
%LAUNCHER% -r "%VIRT_STORE%" cmd /c reg delete "%REG_TARGET%\SubA" /f >nul 2>&1
reg query "%REG_VROOT%\SubA" >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    call :Pass "7.8  Reg Delete Subtree: SubA and all children removed from virtual root"
) else (
    call :Fail "7.8  Reg Delete Subtree: SubA still exists in virtual root after tree delete"
)

:: 7.9  Reg write then read BINARY (REG_BINARY)
::      FIX: "reg query" prints REG_BINARY as "de ad be ef" (space-separated hex).
::      findstr without /C: treats the spaces as OR separators and always matches.
::      Use findstr /C: to search for the exact spaced hex string.
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s7_regbin.bat"
echo reg add "%REG_TARGET%" /v BinVal /t REG_BINARY /d DEADBEEF /f ^>nul>>"%TEST_DIR%\pl_s7_regbin.bat"
echo reg query "%REG_TARGET%" /v BinVal 2^>nul ^| findstr /C:"DEADBEEF" ^>nul>>"%TEST_DIR%\pl_s7_regbin.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s7_regbin.bat"

%LAUNCHER% -r "%VIRT_STORE%" cmd /c "%TEST_DIR%\pl_s7_regbin.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "7.9  Reg BINARY: REG_BINARY written and read back via virtual path"
) else (
    call :Fail "7.9  Reg BINARY: REG_BINARY write/read failed via virtual path"
)

:: 7.10  Reg key isolation: virtual write must NOT leak into the real host key.
::       (Reading through to the real key when no virtual value exists is correct
::       Sandboxie-style behaviour and is NOT tested here.)
::
::       Check: write VirtOnlyVal via VirtLauncher, then verify from the host
::       (outside VirtLauncher) that it does NOT appear in the real REG_TARGET.
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s7_regisolate.bat"
echo reg add "%REG_TARGET%" /v VirtOnlyVal /t REG_SZ /d VirtOnlyData /f ^>nul>>"%TEST_DIR%\pl_s7_regisolate.bat"

%LAUNCHER% -r "%VIRT_STORE%" cmd /c "%TEST_DIR%\pl_s7_regisolate.bat"

:: Value must be in the virtual root
reg query "%REG_VROOT%" /v VirtOnlyVal 2>nul | findstr "VirtOnlyData" >nul
if !ERRORLEVEL! NEQ 0 (
    call :Fail "7.10 Reg Isolation: VirtOnlyVal not found in virtual root (write failed?)"
) else (
    :: Value must NOT be in the real host key
    reg query "%REG_TARGET%" /v VirtOnlyVal >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        call :Fail "7.10 Reg Isolation: virtual write leaked into real host key"
    ) else (
        call :Pass "7.10 Reg Isolation: virtual write stayed in virtual root, did not leak to host"
    )
)
:: Cleanup
reg delete "%REG_VROOT%" /v VirtOnlyVal /f >nul 2>&1


:: ============================================================
:: SECTION 8 -- CHILD PROCESS INJECTION  (CreateProcessW/A hook)
::   VirtLauncher injects VirtHook into the direct child (cmd).
::   The child's CreateProcessW hook then injects into grandchildren.
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 8]  Child Process Injection (Hook Propagation)
echo ============================================================

:: 8.1  Grandchild can read virtualized file
echo ___________________
echo GrandchildContent>"%DST_DIR%\gc_read.txt"
echo @echo off>"%TEST_DIR%\pl_s8_gc_inner.bat"
echo findstr "GrandchildContent" "%SRC_DIR%\gc_read.txt" ^>nul>>"%TEST_DIR%\pl_s8_gc_inner.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s8_gc_inner.bat"

echo @echo off>"%TEST_DIR%\pl_s8_gc_outer.bat"
echo cmd /c "%TEST_DIR%\pl_s8_gc_inner.bat">>"%TEST_DIR%\pl_s8_gc_outer.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s8_gc_outer.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s8_gc_outer.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "8.1  Grandchild Read: grandchild process sees FS virtualization"
) else (
    call :Fail "8.1  Grandchild Read: grandchild does NOT see FS virtualization"
)

:: 8.2  Grandchild write lands in dst (not src)
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s8_gcw_inner.bat"
echo echo GrandchildWrite^>"%SRC_DIR%\gc_write.txt">>"%TEST_DIR%\pl_s8_gcw_inner.bat"

echo @echo off>"%TEST_DIR%\pl_s8_gcw_outer.bat"
echo cmd /c "%TEST_DIR%\pl_s8_gcw_inner.bat">>"%TEST_DIR%\pl_s8_gcw_outer.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s8_gcw_outer.bat"
if exist "%DST_DIR%\gc_write.txt" (
    if not exist "%SRC_DIR%\gc_write.txt" (
        call :Pass "8.2  Grandchild Write: write landed in dst, not src"
    ) else (
        call :Fail "8.2  Grandchild Write: grandchild write leaked into src"
    )
) else (
    call :Fail "8.2  Grandchild Write: grandchild write not found in dst"
)


:: ============================================================
:: SECTION 9 -- ISOLATION / NO-LEAK VERIFICATION
::   These are control tests: they verify that the src directory
::   received no unintentional writes during the entire suite,
::   and that paths outside the redirect zone are not affected.
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 9]  Isolation / No-Leak Verification
echo ============================================================

:: 9.1  Source directory has no leaked files
::      All write operations above should have landed in dst.
echo ___________________
dir "%SRC_DIR%" /b /a >"%TEMP%\vl_src_leak_check.tmp" 2>nul
for %%F in ("%TEMP%\vl_src_leak_check.tmp") do set VL_SRC_FSIZE=%%~zF
if !VL_SRC_FSIZE! EQU 0 (
    call :Pass "9.1  No Src Leak: src directory is empty -- no write leaked to src"
) else (
    call :Fail "9.1  No Src Leak: !VL_SRC_FSIZE! byte(s) of content found in src directory:"
    type "%TEMP%\vl_src_leak_check.tmp"
)
del "%TEMP%\vl_src_leak_check.tmp" 2>nul

:: 9.2  Control: write to a path outside the redirect zone goes to the real location
echo ___________________
set VL_CTRL=%TEMP%\vl_ctrl_%RANDOM%.txt
echo @echo off>"%TEST_DIR%\pl_s9_ctrl.bat"
echo echo ControlContent^>"%VL_CTRL%">>"%TEST_DIR%\pl_s9_ctrl.bat"

%LAUNCHER% -r "%VIRT_STORE%" -c "%INI_FILE%" cmd /c "%TEST_DIR%\pl_s9_ctrl.bat"
if exist "%VL_CTRL%" (
    call :Pass "9.2  Control: write outside redirect zone went to real %TEMP%"
    del "%VL_CTRL%" 2>nul
) else (
    call :Fail "9.2  Control: write outside redirect zone was lost or wrongly redirected"
)

:: 9.3  Without -c flag, writes go to the real path (no hook active)
echo ___________________
set VL_NOHOOK=%TEST_DIR%\nohook_test.txt
echo @echo off>"%TEST_DIR%\pl_s9_nohook.bat"
echo echo NoHookContent^>"%SRC_DIR%\nohook_verify.txt">>"%TEST_DIR%\pl_s9_nohook.bat"

%LAUNCHER% -r "%VIRT_STORE%" cmd /c "%TEST_DIR%\pl_s9_nohook.bat"
if exist "%SRC_DIR%\nohook_verify.txt" (
    call :Pass "9.3  No-Hook Baseline: without -c, writes go to real src path (hook inactive)"
    del "%SRC_DIR%\nohook_verify.txt" 2>nul
) else (
    call :Fail "9.3  No-Hook Baseline: write to src failed even without -c flag"
)


:: ============================================================
:: CLEANUP & SUMMARY
:: ============================================================
echo.
echo [*] Cleaning up test artifacts...
reg delete "%VIRT_STORE%" /f >nul 2>&1
reg delete "%REG_TARGET%" /f >nul 2>&1

:: Detach reparse points before rmdir to avoid access-denied on the tree delete
if exist "%DST_DIR%\junc_link"       rmdir "%DST_DIR%\junc_link"       2>nul
if exist "%DST_DIR%\junc_rd_link"    rmdir "%DST_DIR%\junc_rd_link"    2>nul
if exist "%DST_DIR%\sym_link_dir"    rmdir "%DST_DIR%\sym_link_dir"    2>nul
if exist "%DST_DIR%\sym_rd_link_dir" rmdir "%DST_DIR%\sym_rd_link_dir" 2>nul

:: Strip any read-only attrs so rmdir /s /q doesn't choke
attrib -R "%DST_DIR%\*" /s >nul 2>&1
attrib -R "%SRC_DIR%\*" /s >nul 2>&1
rmdir /s /q "%TEST_DIR%" 2>nul

echo.
echo ============================================================
echo  TEST SUMMARY
echo ============================================================
echo  Passed  : %PASS_COUNT%
echo  Failed  : %FAIL_COUNT%
echo  Skipped : %SKIP_COUNT%
echo ============================================================

if %FAIL_COUNT% equ 0 (
    echo  [OK] ALL TESTS PASSED SUCCESSFULLY!
    color 2F
) else (
    echo  [X] SOME TESTS FAILED!
    color 4F
)

echo.
if not "%DoNotPause%"=="yes" pause
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

:Skip
echo   [~] SKIP: %~1
set /a SKIP_COUNT+=1
goto :eof
