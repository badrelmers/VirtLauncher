@echo off
SETLOCAL EnableDelayedExpansion
CD /D "%~dp0"

REM check admin
@rem fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

::_______________________________________________
REM set VLAUNCHER_VERBOSE=true
REM set VLAUNCHER_DEBUG=true


:: ============================================================
::  VirtLauncher [exclude] Feature Test Suite  (v1)
::
::  Covers:
::    Section 1: [exclude] + --config            basic exclude operations
::    Section 2: [exclude] + --config            deep nesting and sibling paths
::    Section 3: --filesystem flag               catch-all sandbox (no exclude)
::    Section 4: --filesystem + [exclude]        exclude bypass inside sandbox
::    Section 5: Component-boundary guard        prefix != path component
::
::  What is tested per section:
::    Write / Read / Delete / Rename on excluded paths stay on real FS.
::    Non-excluded paths under the same redirect still virtualise normally.
::    Excluded writes do NOT appear in the virtual store.
::    --filesystem catch-all is correctly bypassed for excluded paths.
::    Excluding  foo  never accidentally excludes  foo_sibling  or  foobar.
:: ============================================================

:: ---- Build directory ----
cd "..\build"


:: ---- Launcher (prefer 64-bit) ----
set LAUNCHER=VirtLauncher64.exe
if not exist "%LAUNCHER%" set LAUNCHER=VirtLauncher32.exe
if not exist "%LAUNCHER%" (
    echo [ERROR] VirtLauncher executable not found in build folder.
    pause
    exit /b 1
)

:: ====================================================================
::  Workspace layout
::
::  _excl_test_ws\
::    src\              logical source  (what the app sees)
::      excl\           the directory we will mark as [exclude]
::      excl_sibling\   same parent, shares "excl" as a string prefix
::    dst\              redirect destination for --config tests
::    sandbox1\         --filesystem store  (Section 3, no exclude)
::    sandbox2\         --filesystem store  (Section 4, with exclude)
::    full.ini          [redirect] src->dst  +  [exclude] excl
::    excl_only.ini     [exclude] excl  only  (for --filesystem tests)
:: ====================================================================

set "TEST_DIR=%CD%\_excl_test_ws"
set "SRC_DIR=%TEST_DIR%\src"
set "DST_DIR=%TEST_DIR%\dst"
set "EXCL_DIR=%SRC_DIR%\excl"
set "EXCL_SIBLING=%SRC_DIR%\excl_sibling"
set "SANDBOX1=%TEST_DIR%\sandbox1"
set "SANDBOX2=%TEST_DIR%\sandbox2"
set "FULL_INI=%TEST_DIR%\full.ini"
set "EXCL_ONLY_INI=%TEST_DIR%\excl_only.ini"

:: ---- Compute --filesystem shadow paths --------------------------------
::
::  VirtHook maps:   \??\X:\some\path   ->   \??\<sandboxroot>\X\some\path
::  On disk that is: <sandboxroot>\<DriveLetter><path_without_drive_colon>
::
::  Example:  SRC_DIR = D:\build\_excl_test_ws\src
::    _DL           = D
::    _SRC_TAIL     = \build\_excl_test_ws\src
::    SHADOW1       = %SANDBOX1%\D\build\_excl_test_ws\src
::
for %%D in ("%SRC_DIR%")     do set "_SDRIVE=%%~dD"
set "_DL=!_SDRIVE:~0,1!"
set "_SRC_TAIL=!SRC_DIR:~2!"
set "_EXCL_TAIL=!EXCL_DIR:~2!"
set "_EXCL_SIB_TAIL=!EXCL_SIBLING:~2!"

::  SHADOW1 / SHADOW2  = virtual store copy of SRC_DIR
set "SHADOW1=%SANDBOX1%\!_DL!!_SRC_TAIL!"
set "SHADOW2=%SANDBOX2%\!_DL!!_SRC_TAIL!"

::  EXCL_SHADOW1/2  = where EXCL_DIR *would* land if it were not excluded
set "EXCL_SHADOW1=%SANDBOX1%\!_DL!!_EXCL_TAIL!"
set "EXCL_SHADOW2=%SANDBOX2%\!_DL!!_EXCL_TAIL!"

::  EXCL_SIB_SHADOW2  = where EXCL_SIBLING would land in sandbox2
set "EXCL_SIB_SHADOW2=%SANDBOX2%\!_DL!!_EXCL_SIB_TAIL!"

:: ---- Clean and create workspace ----
rmdir /s /q "%TEST_DIR%" 2>nul
mkdir "%SRC_DIR%"
mkdir "%DST_DIR%"
mkdir "%EXCL_DIR%"
mkdir "%EXCL_SIBLING%"
mkdir "%SANDBOX1%"
mkdir "%SANDBOX2%"

:: ---- full.ini : [redirect] src -> dst  +  [exclude] excl_dir ----
(
    echo # VirtLauncher test config -- redirect + exclude
    echo [redirect]
    echo %SRC_DIR%=%DST_DIR%
    echo.
    echo [exclude]
    echo %EXCL_DIR%
) > "%FULL_INI%"

:: ---- excl_only.ini : [exclude] only, used with --filesystem ----
:: NOTE: no parentheses anywhere inside this block -- a bare ) in an echo
::       line would prematurely close the compound redirect and leave the
::       [exclude] section unwritten (root cause of the section-4 failures).
(
    echo # Test config: exclude only, used paired with --filesystem flag
    echo [exclude]
    echo %EXCL_DIR%
) > "%EXCL_ONLY_INI%"

set /a PASS_COUNT=0
set /a FAIL_COUNT=0
set /a SKIP_COUNT=0

echo ============================================================
echo  VirtLauncher [exclude] Feature Test Suite  v1
echo  Launcher  : %LAUNCHER%
echo  Workspace : %TEST_DIR%
echo  Drive     : !_DL!:
echo  Shadow1   : %SHADOW1%
echo  Shadow2   : %SHADOW2%
echo ============================================================


:: ============================================================
:: SECTION 1 -- [exclude] + --config  (basic operations)
::
::  full.ini redirects SRC_DIR -> DST_DIR and excludes EXCL_DIR.
::  Any path inside EXCL_DIR must pass straight through to the
::  real file system; no file should appear in DST_DIR\excl\.
::
::  Tests: control redirect / write / no-DST-leak /
::         read / delete / rename / if-exist check.
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 1]  [exclude] + --config  (basic operations)
echo ============================================================

:: 1.1  Control -- non-excluded write still redirects to DST
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s1_ctrl.bat"
echo echo RedirContent^>"%SRC_DIR%\ctrl_write.txt">>"%TEST_DIR%\pl_s1_ctrl.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s1_ctrl.bat"
if exist "%DST_DIR%\ctrl_write.txt" (
    if not exist "%SRC_DIR%\ctrl_write.txt" (
        call :Pass "1.1  Control Redirect: non-excluded write landed in DST (redirect active)"
    ) else (
        call :Fail "1.1  Control Redirect: non-excluded write leaked into real SRC"
    )
) else (
    call :Fail "1.1  Control Redirect: non-excluded write not found in DST"
)

:: 1.2  Write to excluded path -- must land on the real FS, inside real EXCL_DIR
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s1_excl_write.bat"
echo echo ExclContent^>"%EXCL_DIR%\excl_write.txt">>"%TEST_DIR%\pl_s1_excl_write.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s1_excl_write.bat"
if exist "%EXCL_DIR%\excl_write.txt" (
    call :Pass "1.2  Exclude Write: write to excluded path landed on real FS"
) else (
    call :Fail "1.2  Exclude Write: write to excluded path did not reach real FS"
)

:: 1.3  Excluded write must NOT have been redirected into DST
echo ___________________
if not exist "%DST_DIR%\excl\excl_write.txt" (
    call :Pass "1.3  Exclude No-DST-Leak: excluded write did not appear in DST"
) else (
    call :Fail "1.3  Exclude No-DST-Leak: excluded write was incorrectly redirected to DST"
)

:: 1.4  Read from excluded path -- reads the real file directly
echo ___________________
echo ExclReadContent>"%EXCL_DIR%\excl_read.txt"
echo @echo off>"%TEST_DIR%\pl_s1_excl_read.bat"
echo findstr "ExclReadContent" "%EXCL_DIR%\excl_read.txt" ^>nul>>"%TEST_DIR%\pl_s1_excl_read.bat"
echo exit /b %%ERRORLEVEL%%>>"%TEST_DIR%\pl_s1_excl_read.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s1_excl_read.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "1.4  Exclude Read: read from excluded path returned real file content"
) else (
    call :Fail "1.4  Exclude Read: failed to read real file via excluded path"
)

:: 1.5  if-exist on excluded path -- NtQueryAttributesFile reads real FS
echo ___________________
echo ExclExistContent>"%EXCL_DIR%\excl_exist.txt"
echo @echo off>"%TEST_DIR%\pl_s1_excl_exist.bat"
echo if exist "%EXCL_DIR%\excl_exist.txt" (exit /b 0) else (exit /b 1)>>"%TEST_DIR%\pl_s1_excl_exist.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s1_excl_exist.bat"
if !ERRORLEVEL! EQU 0 (
    call :Pass "1.5  Exclude Exist Check: real file visible via excluded path (NtQueryAttributesFile)"
) else (
    call :Fail "1.5  Exclude Exist Check: real file not visible via excluded path"
)

:: 1.6  Delete in excluded path -- must delete the real file
echo ___________________
echo DeleteMe>"%EXCL_DIR%\excl_del.txt"
echo @echo off>"%TEST_DIR%\pl_s1_excl_del.bat"
echo del "%EXCL_DIR%\excl_del.txt">>"%TEST_DIR%\pl_s1_excl_del.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s1_excl_del.bat"
if not exist "%EXCL_DIR%\excl_del.txt" (
    call :Pass "1.6  Exclude Delete: real file deleted via excluded path"
) else (
    call :Fail "1.6  Exclude Delete: real file still present after delete via excluded path"
)

:: 1.7  Rename in excluded path -- must rename the real file
echo ___________________
echo RenameMe>"%EXCL_DIR%\excl_ren_orig.txt"
echo @echo off>"%TEST_DIR%\pl_s1_excl_ren.bat"
echo rename "%EXCL_DIR%\excl_ren_orig.txt" excl_ren_new.txt>>"%TEST_DIR%\pl_s1_excl_ren.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s1_excl_ren.bat"
if exist "%EXCL_DIR%\excl_ren_new.txt" (
    if not exist "%EXCL_DIR%\excl_ren_orig.txt" (
        call :Pass "1.7  Exclude Rename: rename operated on real file inside excluded path"
    ) else (
        call :Fail "1.7  Exclude Rename: original file still present after rename"
    )
) else (
    call :Fail "1.7  Exclude Rename: renamed file not found in real excluded dir"
)

:: 1.8  Append write to excluded path -- stays on real FS
echo ___________________
echo LineOne>"%EXCL_DIR%\excl_append.txt"
echo @echo off>"%TEST_DIR%\pl_s1_excl_append.bat"
echo echo LineTwo^>^>"%EXCL_DIR%\excl_append.txt">>"%TEST_DIR%\pl_s1_excl_append.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s1_excl_append.bat"
findstr "LineTwo" "%EXCL_DIR%\excl_append.txt" >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    call :Pass "1.8  Exclude Append: appended content in real excluded file, not DST"
) else (
    call :Fail "1.8  Exclude Append: append did not land in real excluded file"
)


:: ============================================================
:: SECTION 2 -- Deep nesting and sibling paths
::
::  The excluded prefix is  SRC_DIR\excl.
::  Tests verify that:
::    a) sub-subdirectories of the excluded path are also excluded.
::    b) a sibling path that shares the prefix string  (excl_sibling)
::       is correctly NOT excluded.
::    c) a new file created inside the excluded dir from scratch (no
::       pre-planted real file) still lands on the real FS.
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 2]  Deep Nesting and Sibling Paths
echo ============================================================

:: 2.1  Deep exclude -- sub-subdirectory inside EXCL_DIR is also excluded
echo ___________________
mkdir "%EXCL_DIR%\deep\deeper" 2>nul
echo @echo off>"%TEST_DIR%\pl_s2_deep.bat"
echo echo DeepContent^>"%EXCL_DIR%\deep\deeper\deep_write.txt">>"%TEST_DIR%\pl_s2_deep.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s2_deep.bat"
if exist "%EXCL_DIR%\deep\deeper\deep_write.txt" (
    if not exist "%DST_DIR%\excl\deep\deeper\deep_write.txt" (
        call :Pass "2.1  Deep Exclude: sub-subdirectory write landed on real FS (not DST)"
    ) else (
        call :Fail "2.1  Deep Exclude: sub-subdirectory write incorrectly appeared in DST"
    )
) else (
    call :Fail "2.1  Deep Exclude: sub-subdirectory write did not reach real FS"
)

:: 2.2  Sibling redirect -- excl_sibling is NOT excluded, must still redirect to DST
::
::      EXCL_DIR     = SRC_DIR\excl
::      EXCL_SIBLING = SRC_DIR\excl_sibling
::
::      "excl" IS a string prefix of "excl_sibling".
::      Without the component-boundary guard, excl_sibling would be wrongly excluded.
::      Correct behaviour: excl_sibling write goes to DST\excl_sibling\.
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s2_sibling.bat"
echo echo SiblingContent^>"%EXCL_SIBLING%\sib_write.txt">>"%TEST_DIR%\pl_s2_sibling.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s2_sibling.bat"
if exist "%DST_DIR%\excl_sibling\sib_write.txt" (
    if not exist "%EXCL_SIBLING%\sib_write.txt" (
        call :Pass "2.2  Sibling Redirect: excl_sibling correctly redirected to DST (not treated as excluded)"
    ) else (
        call :Fail "2.2  Sibling Redirect: sibling write leaked to real FS (wrongly treated as excluded)"
    )
) else (
    call :Fail "2.2  Sibling Redirect: sibling write not found in DST"
)

:: 2.3  Positive control -- exact excluded path still excluded (not broken by sibling test)
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s2_excl_confirm.bat"
echo echo ExclConfirm^>"%EXCL_DIR%\sec2_confirm.txt">>"%TEST_DIR%\pl_s2_excl_confirm.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s2_excl_confirm.bat"
if exist "%EXCL_DIR%\sec2_confirm.txt" (
    if not exist "%DST_DIR%\excl\sec2_confirm.txt" (
        call :Pass "2.3  Positive Control: exact excluded path still excluded after sibling test"
    ) else (
        call :Fail "2.3  Positive Control: excluded path write incorrectly appeared in DST"
    )
) else (
    call :Fail "2.3  Positive Control: excluded path write did not reach real FS"
)


:: ============================================================
:: SECTION 3 -- --filesystem flag  (catch-all sandbox, no exclude)
::
::  %LAUNCHER% -f <sandbox> redirects ALL paths on ALL drive letters
::  into the sandbox virtual store.
::
::  Shadow path layout:
::    real:   X:\some\path\file.txt
::    shadow: <sandbox>\X\some\path\file.txt
::
::  IMPORTANT -- no bat-file intermediaries in this section.
::  The -f flag catches the ENTIRE drive (all drive letters), including
::  TEST_DIR itself.  If a payload were a .bat file inside TEST_DIR,
::  VirtHook would redirect cmd's lookup for that .bat into the shadow
::  where it does not exist ("not recognized as an internal or external
::  command").  All launcher invocations here pass the command inline
::  via cmd /c "..." so no on-disk bat file is looked up through the hook.
::
::  Note on test 3.5: the original "write outside coverage zone" control
::  from suite2 is meaningless here -- -f covers ALL drive letters, so
::  there is no regular path outside the sandbox.  3.5 is replaced with
::  an append test, which exercises NtCreateFile with FILE_OPEN disposition
::  (a distinct code path from the truncating create in 3.1).
::
::  Tests: write / read / if-exist / delete / append.
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 3]  --filesystem flag  (catch-all sandbox, no exclude)
echo ============================================================

:: 3.1  Write via -f: must create file in the sandbox shadow, not the real SRC_DIR
echo ___________________
%LAUNCHER% -f "%SANDBOX1%" cmd /S /c "echo FsContent>"%SRC_DIR%\fs_write.txt" "
if exist "%SHADOW1%\fs_write.txt" (
    if not exist "%SRC_DIR%\fs_write.txt" (
        call :Pass "3.1  FS Write: file created in sandbox shadow, not real SRC_DIR"
    ) else (
        call :Fail "3.1  FS Write: file leaked into real SRC_DIR"
    )
) else (
    call :Fail "3.1  FS Write: file not found in sandbox shadow (%SHADOW1%)"
)

:: 3.2  Read via -f: plant a file in the shadow, read via the logical SRC path
echo ___________________
mkdir "%SHADOW1%" 2>nul
echo FsReadContent>"%SHADOW1%\fs_read.txt"
%LAUNCHER% -f "%SANDBOX1%" cmd /S /c "findstr FsReadContent "%SRC_DIR%\fs_read.txt" >nul"
if !ERRORLEVEL! EQU 0 (
    call :Pass "3.2  FS Read: sandbox shadow file readable via logical SRC path"
) else (
    call :Fail "3.2  FS Read: failed to read file from sandbox shadow"
)

:: 3.3  if-exist via -f: shadow file must be visible to existence check
echo ___________________
echo FsExistContent>"%SHADOW1%\fs_exist.txt"
%LAUNCHER% -f "%SANDBOX1%" cmd /S /c "if exist "%SRC_DIR%\fs_exist.txt" (exit /b 0) else (exit /b 1)"
if !ERRORLEVEL! EQU 0 (
    call :Pass "3.3  FS Exist Check: shadow file visible via logical SRC path (NtQueryAttributesFile)"
) else (
    call :Fail "3.3  FS Exist Check: shadow file not visible via logical SRC path"
)

:: 3.4  Delete via -f: plant in shadow, delete via logical path, must remove from shadow
echo ___________________
echo DeleteMe>"%SHADOW1%\fs_del.txt"
%LAUNCHER% -f "%SANDBOX1%" cmd /S /c "del "%SRC_DIR%\fs_del.txt" "
if not exist "%SHADOW1%\fs_del.txt" (
    call :Pass "3.4  FS Delete: delete via logical path removed file from sandbox shadow"
) else (
    call :Fail "3.4  FS Delete: sandbox shadow file still present after delete"
)

:: 3.5  Append via -f: plant a file in shadow, append a second line via logical path.
::      Exercises NtCreateFile with FILE_OPEN/append disposition -- different code path
::      from the truncating create in 3.1.
echo ___________________
echo LineOne>"%SHADOW1%\fs_append.txt"
%LAUNCHER% -f "%SANDBOX1%" cmd /S /c "echo LineTwo>>"%SRC_DIR%\fs_append.txt" "
findstr "LineTwo" "%SHADOW1%\fs_append.txt" >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    if not exist "%SRC_DIR%\fs_append.txt" (
        call :Pass "3.5  FS Append: second line appended in shadow, no leak to real SRC"
    ) else (
        call :Fail "3.5  FS Append: append leaked into real SRC_DIR"
    )
) else (
    call :Fail "3.5  FS Append: second line not found in shadow file after append"
)


:: ============================================================
:: SECTION 4 -- --filesystem + [exclude]  (combined)
::
::  excl_only.ini holds only [exclude] EXCL_DIR.
::  Launch uses:   %LAUNCHER% -f <sandbox2> -c <excl_only.ini>
::
::  Expected behaviour:
::    - Writes to SRC_DIR (non-excluded) -> shadow2
::    - Writes to EXCL_DIR (excluded)    -> real FS  (bypasses -f entirely)
::    - Excluded writes must NOT appear in shadow2
::    - Excluded reads must come from real FS, not shadow2
::
::  Same inline cmd /c "..." pattern as section 3 -- bat-file
::  intermediaries would be shadowed to a non-existent location.
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 4]  --filesystem + [exclude]  (combined)
echo ============================================================

:: 4.1  Non-excluded path: write must still land in sandbox shadow2
echo ___________________
%LAUNCHER% -f "%SANDBOX2%" -c "%EXCL_ONLY_INI%" cmd /S /c "echo SandboxContent>"%SRC_DIR%\fsexcl_write.txt" "
if exist "%SHADOW2%\fsexcl_write.txt" (
    if not exist "%SRC_DIR%\fsexcl_write.txt" (
        call :Pass "4.1  FS+Excl Write: non-excluded path correctly goes to sandbox shadow"
    ) else (
        call :Fail "4.1  FS+Excl Write: non-excluded path leaked to real SRC_DIR"
    )
) else (
    call :Fail "4.1  FS+Excl Write: non-excluded path not found in sandbox shadow"
)

:: 4.2  Excluded path: write must bypass sandbox and land on real FS
echo ___________________
%LAUNCHER% -f "%SANDBOX2%" -c "%EXCL_ONLY_INI%" cmd /S /c "echo ExclBypass>"%EXCL_DIR%\fsexcl_excl_write.txt" "
if exist "%EXCL_DIR%\fsexcl_excl_write.txt" (
    call :Pass "4.2  FS+Excl Bypass Write: excluded path bypasses sandbox, write lands on real FS"
) else (
    call :Fail "4.2  FS+Excl Bypass Write: excluded path write did not reach real FS"
)

:: 4.3  Excluded write must NOT have appeared in sandbox shadow2
echo ___________________
if not exist "%EXCL_SHADOW2%\fsexcl_excl_write.txt" (
    call :Pass "4.3  FS+Excl No Shadow Leak: excluded write absent from sandbox shadow"
) else (
    call :Fail "4.3  FS+Excl No Shadow Leak: excluded write incorrectly appeared in sandbox shadow"
)

:: 4.4  Read from excluded path: must read from real FS, not shadow
::      Plant a decoy with different content in shadow2 and the real
::      content in the real EXCL_DIR. The app must read the real one.
echo ___________________
echo RealFileContent>"%EXCL_DIR%\fsexcl_read.txt"
mkdir "%EXCL_SHADOW2%" 2>nul
echo DecoyInShadow>"%EXCL_SHADOW2%\fsexcl_read.txt"
%LAUNCHER% -f "%SANDBOX2%" -c "%EXCL_ONLY_INI%" cmd /S /c "findstr RealFileContent "%EXCL_DIR%\fsexcl_read.txt" >nul"
if !ERRORLEVEL! EQU 0 (
    call :Pass "4.4  FS+Excl Read: excluded path returned real FS content, not sandbox decoy"
) else (
    call :Fail "4.4  FS+Excl Read: excluded path did not return real FS content (decoy may have been read)"
)

:: 4.5  Delete in excluded path: must delete the real file, not the shadow decoy
echo ___________________
echo RealDeleteTarget>"%EXCL_DIR%\fsexcl_del.txt"
echo ShadowDecoy>"%EXCL_SHADOW2%\fsexcl_del.txt"
%LAUNCHER% -f "%SANDBOX2%" -c "%EXCL_ONLY_INI%" cmd /S /c "del "%EXCL_DIR%\fsexcl_del.txt" "
if not exist "%EXCL_DIR%\fsexcl_del.txt" (
    if exist "%EXCL_SHADOW2%\fsexcl_del.txt" (
        call :Pass "4.5  FS+Excl Delete: real file deleted, shadow decoy untouched"
    ) else (
        call :Fail "4.5  FS+Excl Delete: both real and shadow files gone (shadow should be untouched)"
    )
) else (
    call :Fail "4.5  FS+Excl Delete: real file still present after delete via excluded path"
)


:: ============================================================
:: SECTION 5 -- Component-boundary guard
::
::  EXCL_DIR     = SRC_DIR\excl
::  EXCL_SIBLING = SRC_DIR\excl_sibling
::
::  "excl" is a string prefix of "excl_sibling", so without the
::  component-boundary guard the sibling would be wrongly excluded.
::  The guard ensures the character right after the prefix in the
::  candidate path must be  \  (or end-of-string), not  _  or any
::  other letter.
::
::  Tests:
::    5.1  excl_sibling write still redirects (not mis-excluded)
::    5.2  excl itself still excluded (guard did not break exact match)
::    5.3  sub-path of excl_sibling also still redirects
::    5.4  sub-path of excl is still excluded (recursive prefix ok)
:: ============================================================
echo.
echo ============================================================
echo  [SECTION 5]  Component-Boundary Guard
echo ============================================================

:: 5.1  excl_sibling redirects to DST -- must NOT be treated as excluded
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s5_sib_redir.bat"
echo echo GuardTestSibling^>"%EXCL_SIBLING%\guard_sib.txt">>"%TEST_DIR%\pl_s5_sib_redir.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s5_sib_redir.bat"
if exist "%DST_DIR%\excl_sibling\guard_sib.txt" (
    if not exist "%EXCL_SIBLING%\guard_sib.txt" (
        call :Pass "5.1  Guard Sibling Redirect: excl_sibling correctly redirected (not mis-excluded)"
    ) else (
        call :Fail "5.1  Guard Sibling Redirect: excl_sibling wrongly bypassed redirect (mis-excluded)"
    )
) else (
    call :Fail "5.1  Guard Sibling Redirect: excl_sibling write not found in DST"
)

:: 5.2  excl itself still excluded after sibling test (exact match still works)
echo ___________________
echo @echo off>"%TEST_DIR%\pl_s5_excl_exact.bat"
echo echo GuardTestExact^>"%EXCL_DIR%\guard_exact.txt">>"%TEST_DIR%\pl_s5_excl_exact.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s5_excl_exact.bat"
if exist "%EXCL_DIR%\guard_exact.txt" (
    if not exist "%DST_DIR%\excl\guard_exact.txt" (
        call :Pass "5.2  Guard Exact Exclude: exact excluded path still bypasses redirect correctly"
    ) else (
        call :Fail "5.2  Guard Exact Exclude: excluded path write incorrectly appeared in DST"
    )
) else (
    call :Fail "5.2  Guard Exact Exclude: exact excluded path write did not reach real FS"
)

:: 5.3  Sub-path of excl_sibling also redirects (not mis-excluded)
echo ___________________
mkdir "%EXCL_SIBLING%\sub" 2>nul
echo @echo off>"%TEST_DIR%\pl_s5_sib_sub.bat"
echo echo GuardSubSibling^>"%EXCL_SIBLING%\sub\guard_sib_sub.txt">>"%TEST_DIR%\pl_s5_sib_sub.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s5_sib_sub.bat"
if exist "%DST_DIR%\excl_sibling\sub\guard_sib_sub.txt" (
    if not exist "%EXCL_SIBLING%\sub\guard_sib_sub.txt" (
        call :Pass "5.3  Guard Sibling Sub-path: excl_sibling\sub correctly redirected (not mis-excluded)"
    ) else (
        call :Fail "5.3  Guard Sibling Sub-path: excl_sibling\sub wrongly bypassed redirect"
    )
) else (
    call :Fail "5.3  Guard Sibling Sub-path: excl_sibling\sub write not found in DST"
)

:: 5.4  Sub-path of excl is also excluded (recursive prefix match works)
echo ___________________
mkdir "%EXCL_DIR%\sub" 2>nul
echo @echo off>"%TEST_DIR%\pl_s5_excl_sub.bat"
echo echo GuardSubExcl^>"%EXCL_DIR%\sub\guard_excl_sub.txt">>"%TEST_DIR%\pl_s5_excl_sub.bat"

%LAUNCHER% -c "%FULL_INI%" cmd /c "%TEST_DIR%\pl_s5_excl_sub.bat"
if exist "%EXCL_DIR%\sub\guard_excl_sub.txt" (
    if not exist "%DST_DIR%\excl\sub\guard_excl_sub.txt" (
        call :Pass "5.4  Guard Sub-path Exclude: sub-path of excluded dir also excluded (recursive)"
    ) else (
        call :Fail "5.4  Guard Sub-path Exclude: sub-path of excluded dir incorrectly appeared in DST"
    )
) else (
    call :Fail "5.4  Guard Sub-path Exclude: sub-path of excluded dir did not reach real FS"
)


:: ============================================================
:: CLEANUP & SUMMARY
:: ============================================================
echo.
echo [*] Cleaning up test artifacts...
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

:Skip
echo   [~] SKIP: %~1
set /a SKIP_COUNT+=1
goto :eof
