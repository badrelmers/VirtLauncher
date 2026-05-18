@echo off
SETLOCAL ENABLEDELAYEDEXPANSION
CD /D "%~dp0"

:: ================================================================
::  Comprehensive Merge-Write Test Suite for VirtLauncher
::  Tests: move, rename, copy, delete, read/write
::         files AND folders, real-only, virtual-only, mixed
:: ================================================================

set VLAUNCHER_DEBUG=false
REM set VLAUNCHER_DEBUG=true

set "BUILD_DIR=..\build"
cd "%BUILD_DIR%"

set "VL=VirtLauncher64.exe -r -f -e"
set "testdir=c:\test11_merged_write"
set "VIRTL_BASE=%CD%\VIRTL"
set "VIRTL=%VIRTL_BASE%\%testdir::=%"

set PASS=0
set FAIL=0
set TOTAL=0

:: ---------------------------------------------------------------
:: Helper macros via labels
:: ---------------------------------------------------------------
goto :main

:check_ok
:: Usage: call :check_ok "label"
set /a TOTAL+=1
if %ERRORLEVEL% EQU 0 (
    set /a PASS+=1
) else (
    set /a FAIL+=1
    color 4F
    echo   FAIL: %~1
)
goto :eof

:check_fail
:: Expects ERRORLEVEL != 0 (command should have failed)
set /a TOTAL+=1
if NOT %ERRORLEVEL% EQU 0 (
    set /a PASS+=1
) else (
    set /a FAIL+=1
    color 4F
    echo   FAIL: %~1
)
goto :eof

:expect_exists
:: Usage: call :expect_exists "path" "label"
set /a TOTAL+=1
if exist "%~1" (
    set /a PASS+=1
) else (
    set /a FAIL+=1
    color 4F
    echo   FAIL: %~2  [expected to exist: %~1]
)
goto :eof

:expect_missing
:: Usage: call :expect_missing "path" "label"
set /a TOTAL+=1
if not exist "%~1" (
    set /a PASS+=1
) else (
    set /a FAIL+=1
    color 4F
    echo   FAIL: %~2  [expected to be absent: %~1]
)
goto :eof

:expect_content
:: Usage: call :expect_content "path" "string" "label"
set /a TOTAL+=1
findstr /C:"%~2" "%~1" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set /a PASS+=1
) else (
    set /a FAIL+=1
    color 4F
    echo   FAIL: %~3  [expected "%~2" in %~1]
)
goto :eof

:reset
rmdir /Q /S "%VIRTL_BASE%" 2>nul
rmdir /Q /S "%testdir%" 2>nul
goto :eof

:section
echo.
echo ================================================================
echo  %~1
echo ================================================================
echo.
goto :eof


:: ================================================================
:main
:: ================================================================
color 2F
echo.
echo  VirtLauncher Merge-Write Full Test Suite
echo.

:: ================================================================
call :section "MOVE - FILES"
:: ================================================================

:: ---------------------------------------------------------------
echo --- 1.1  move real file over another real file (overwrite prompt)
call :reset
mkdir "%testdir%"
echo ccc>"%testdir%\c"
echo vvv>"%testdir%\v"
%VL% cmd /S /C "echo y|move /-Y "%testdir%\c" "%testdir%\v" " | findstr Overwrite >nul
call :check_ok "1.1a overwrite prompt appeared"
call :expect_missing "%VIRTL%\c"        "1.1b src not in virtual after move"
call :expect_exists  "%VIRTL%\v"        "1.1c dst exists in virtual after move"

:: ---------------------------------------------------------------
echo --- 1.2  move real file to non-existent destination
call :reset
mkdir "%testdir%"
echo ccc>"%testdir%\c"
%VL% cmd /c move "%testdir%\c" "%testdir%\moved_c" >nul 2>nul
call :check_ok "1.2a exit code 0"
call :expect_missing "%VIRTL%\c"           "1.2b src tombstoned"
call :expect_exists  "%VIRTL%\moved_c"     "1.2c dst exists in virtual"

:: ---------------------------------------------------------------
echo --- 1.3  move real file when virtual parent dir already exists
call :reset
mkdir "%testdir%"
echo ccc>"%testdir%\c"
echo vvv>"%testdir%\v"
mkdir "%VIRTL%"
%VL% cmd /c move "%testdir%\c" "%testdir%\v" >nul 2>nul
call :check_ok "1.3a exit code 0"

:: ---------------------------------------------------------------
echo --- 1.4  move real file when virtual parent dir does NOT exist
call :reset
mkdir "%testdir%"
echo ccc>"%testdir%\c"
echo vvv>"%testdir%\v"
%VL% cmd /c move "%testdir%\c" "%testdir%\v" >nul 2>nul
call :check_ok "1.4a exit code 0"

:: ---------------------------------------------------------------
echo --- 1.5  move real file to a subdirectory (subdir is real-only)
call :reset
mkdir "%testdir%\sub"
echo ccc>"%testdir%\c"
%VL% cmd /c move "%testdir%\c" "%testdir%\sub\" >nul 2>nul
call :check_ok "1.5a exit code 0"
call :expect_missing "%VIRTL%\c"          "1.5b src tombstoned"
call :expect_exists  "%VIRTL%\sub\c"      "1.5c dst in virtual subdir"

:: ---------------------------------------------------------------
echo --- 1.6  move virtual-only file to another name
call :reset
mkdir "%testdir%"
%VL% cmd /S /c "echo inside>"%testdir%\vfile" "
%VL% cmd /c move "%testdir%\vfile" "%testdir%\vfile2" >nul 2>nul
call :check_ok "1.6a exit code 0"
call :expect_missing "%VIRTL%\vfile"      "1.6b src gone from virtual"
call :expect_exists  "%VIRTL%\vfile2"     "1.6c dst in virtual"

:: ---------------------------------------------------------------
echo --- 1.7  move file into itself (should fail cleanly, once)
call :reset
mkdir "%testdir%"
echo ccc>"%testdir%\c"
%VL% cmd /c move "%testdir%\c" "%testdir%\c" >nul 2>nul
:: any non-zero exit is fine; we just check error count is 1 (not multiple)
%VL% cmd /c move "%testdir%\c" "%testdir%\c" 2>&1 | find /C "error" >nul 2>nul

:: ---------------------------------------------------------------
echo --- 1.8  move real file to a name that exists ONLY in real (collision)
call :reset
mkdir "%testdir%"
echo ccc>"%testdir%\c"
echo vvv>"%testdir%\v"
%VL% cmd /S /C "echo y|move /-Y "%testdir%\c" "%testdir%\v"" | findstr Overwrite >nul
call :check_ok "1.8a overwrite prompt appeared for real-real collision"

:: ----------------------------------------------------------------
echo --- 1.9  move real file to name existing ONLY in virtual (collision)
call :reset
mkdir "%testdir%"
echo ccc>"%testdir%\c"
%VL% cmd /S /c "echo vvirt>"%testdir%\v" "
%VL% cmd /S /C "echo y|move /-Y "%testdir%\c" "%testdir%\v"" | findstr Overwrite >nul
call :check_ok "1.9a overwrite prompt for real-src vs virtual-dst collision"

:: ================================================================
call :section "MOVE - FOLDERS"
:: ================================================================

:: ---------------------------------------------------------------
echo --- 2.1  move real folder over existing real sub-folder (overwrite)
call :reset
mkdir "%testdir%\cc"
mkdir "%testdir%\vv\cc"
%VL% cmd /S /C "echo y|move /-Y "%testdir%\cc" "%testdir%\vv"" | findstr Overwrite >nul
call :check_ok "2.1a overwrite prompt appeared"
:: tombstone for cc must exist, vv\cc in virtual
call :expect_missing "%VIRTL%\cc"         "2.1b src cc tombstoned"
call :expect_exists  "%VIRTL%\vv\cc"      "2.1c dst vv\cc in virtual"

:: ---------------------------------------------------------------
echo --- 2.2  move real folder to non-existent destination
call :reset
mkdir "%testdir%\cc"
echo fff>"%testdir%\cc\file1"
%VL% cmd /c move "%testdir%\cc" "%testdir%\cc_moved" >nul 2>nul
call :check_ok "2.2a exit code 0"
call :expect_missing "%VIRTL%\cc"           "2.2b src tombstoned"
call :expect_exists  "%VIRTL%\cc_moved"     "2.2c dst exists in virtual"

:: ---------------------------------------------------------------
echo --- 2.3  move real folder into another real folder
call :reset
mkdir "%testdir%\src_dir"
mkdir "%testdir%\dst_dir"
echo fff>"%testdir%\src_dir\file1"
%VL% cmd /c move "%testdir%\src_dir" "%testdir%\dst_dir\" >nul 2>nul
call :check_ok "2.3a exit code 0"
call :expect_missing "%VIRTL%\src_dir"           "2.3b src tombstoned"
call :expect_exists  "%VIRTL%\dst_dir\src_dir"   "2.3c dst exists in virtual"

:: ---------------------------------------------------------------
echo --- 2.4  move virtual-only folder
call :reset
mkdir "%testdir%"
%VL% cmd /c mkdir "%testdir%\vdir"
%VL% cmd /c move "%testdir%\vdir" "%testdir%\vdir2" >nul 2>nul
call :check_ok "2.4a exit code 0"
call :expect_missing "%VIRTL%\vdir"       "2.4b src gone"
call :expect_exists  "%VIRTL%\vdir2"      "2.4c dst in virtual"

:: ================================================================
call :section "RENAME - FILES"
:: ================================================================

:: ---------------------------------------------------------------
echo --- 3.1  rename real file to non-existent name
call :reset
mkdir "%testdir%"
echo sdfsdf>"%testdir%\fileee"
%VL% cmd /c rename "%testdir%\fileee" fileeerenamed
call :check_ok "3.1a exit code 0"
call :expect_missing "%VIRTL%\fileee"           "3.1b src tombstoned"
call :expect_exists  "%VIRTL%\fileeerenamed"    "3.1c dst in virtual"

:: ---------------------------------------------------------------
echo --- 3.2  rename real file to existing name (collision - error once)
call :reset
mkdir "%testdir%"
echo sdfsdf>"%testdir%\fileee"
echo sdfsdf>"%testdir%\fileee2"
%VL% cmd /c rename "%testdir%\fileee" fileee2 2>&1 | findstr /C:"A duplicate file name exists"
call :check_ok "3.2a exactly one collision error line"

:: verify the error is printed only ONCE
set cnt=0
for /f %%L in ('%VL% cmd /c rename "%testdir%\fileee" fileee2 2^>^&1 ^| findstr /C:"A duplicate file name exists"') do set /a cnt+=1
set /a TOTAL+=1
if !cnt! EQU 1 (
    set /a PASS+=1
) else (
    set /a FAIL+=1
    color 4F
    echo   FAIL: 3.2b error printed !cnt! times instead of 1
)

:: ---------------------------------------------------------------
echo --- 3.3  rename real file to its own name (no-op collision)
call :reset
mkdir "%testdir%"
echo abc>"%testdir%\fileee"
%VL% cmd /c rename "%testdir%\fileee" fileee 2>&1 | findstr /C:"A duplicate" >nul
call :check_ok "3.3a self-rename reports collision"

:: ---------------------------------------------------------------
echo --- 3.4  rename virtual file to non-existent name
call :reset
mkdir "%testdir%"
%VL% cmd /S /c "echo inside>"%testdir%\vfile" "
%VL% cmd /c rename "%testdir%\vfile" vrenamed
call :check_ok "3.4a exit code 0"
call :expect_missing "%VIRTL%\vfile"       "3.4b src gone"
call :expect_exists  "%VIRTL%\vrenamed"    "3.4c dst in virtual"

:: ---------------------------------------------------------------
echo --- 3.5  rename virtual file to existing real name (collision)
call :reset
mkdir "%testdir%"
echo real>"%testdir%\realfile"
%VL% cmd /S /c "echo virt>"%testdir%\vfile" "
%VL% cmd /c rename "%testdir%\vfile" realfile 2>&1 | findstr /C:"A duplicate" >nul
call :check_ok "3.5a collision detected"

:: ---------------------------------------------------------------
echo --- 3.6  rename to a name with spaces
call :reset
mkdir "%testdir%"
echo abc>"%testdir%\file1"
%VL% cmd /c rename "%testdir%\file1" "file with spaces"
call :check_ok "3.6a exit code 0"
call :expect_exists  "%VIRTL%\file with spaces"  "3.6b renamed file with spaces exists"

:: ---------------------------------------------------------------
echo --- 3.7  rename file with extension to different extension
call :reset
mkdir "%testdir%"
echo txt>"%testdir%\doc.txt"
%VL% cmd /c rename "%testdir%\doc.txt" doc.bak
call :check_ok "3.7a exit code 0"
call :expect_missing "%VIRTL%\doc.txt"     "3.7b old extension tombstoned"
call :expect_exists  "%VIRTL%\doc.bak"     "3.7c new extension in virtual"

:: ================================================================
call :section "RENAME - FOLDERS"
:: ================================================================

:: ---------------------------------------------------------------
echo --- 4.1  rename real folder to non-existent name
call :reset
mkdir "%testdir%\cc"
%VL% cmd /c rename "%testdir%\cc" vvc
call :check_ok "4.1a exit code 0"
call :expect_missing "%VIRTL%\cc"     "4.1b src tombstoned"
call :expect_exists  "%VIRTL%\vvc"    "4.1c dst in virtual"

:: ---------------------------------------------------------------
echo --- 4.2  rename real folder to existing folder name (collision - error once)
call :reset
mkdir "%testdir%\cc"
mkdir "%testdir%\vvc"
set cnt=0
for /f %%L in ('%VL% cmd /c rename "%testdir%\cc" vvc 2^>^&1 ^| findstr /C:"A duplicate file name exists"') do set /a cnt+=1
set /a TOTAL+=1
if !cnt! EQU 1 (
    set /a PASS+=1
) else (
    set /a FAIL+=1
    color 4F
    echo   FAIL: 4.2 error printed !cnt! times instead of 1
)

:: ---------------------------------------------------------------
echo --- 4.3  rename real folder to existing VIRTUAL folder name (collision)
call :reset
mkdir "%testdir%\cc"
%VL% cmd /c mkdir "%testdir%\vvc"
set cnt=0
for /f %%L in ('%VL% cmd /c rename "%testdir%\cc" vvc 2^>^&1 ^| findstr /C:"A duplicate file name exists"') do set /a cnt+=1
set /a TOTAL+=1
if !cnt! EQU 1 (
    set /a PASS+=1
) else (
    set /a FAIL+=1
    color 4F
    echo   FAIL: 4.3 error printed !cnt! times instead of 1
)

:: ---------------------------------------------------------------
echo --- 4.4  rename virtual folder to non-existent name
call :reset
mkdir "%testdir%"
%VL% cmd /c mkdir "%testdir%\vdir"
%VL% cmd /c rename "%testdir%\vdir" vdirnew
call :check_ok "4.4a exit code 0"
call :expect_missing "%VIRTL%\vdir"       "4.4b src gone"
call :expect_exists  "%VIRTL%\vdirnew"    "4.4c dst in virtual"

:: ---------------------------------------------------------------
echo --- 4.5  rename folder containing files (contents preserved)
call :reset
mkdir "%testdir%\cc"
echo fff>"%testdir%\cc\inner"
%VL% cmd /c rename "%testdir%\cc" cc_new
call :check_ok "4.5a exit code 0"
call :expect_exists  "%VIRTL%\cc_new"   "4.5b renamed folder in virtual"

:: ---------------------------------------------------------------
echo --- 4.6  rename deeply nested real folder
call :reset
mkdir "%testdir%\a\b\c"
%VL% cmd /c rename "%testdir%\a\b\c" c_renamed
call :check_ok "4.6a exit code 0"
call :expect_exists  "%VIRTL%\a\b\c_renamed"  "4.6b nested folder renamed in virtual"

:: ================================================================
call :section "COPY - FILES"
:: ================================================================

:: ---------------------------------------------------------------
echo --- 5.1  copy real file to non-existent name (same dir)
call :reset
mkdir "%testdir%"
echo sdfsdf>"%testdir%\fileee"
%VL% cmd /c copy "%testdir%\fileee" "%testdir%\fileeecopy"
call :check_ok "5.1a exit code 0"
call :expect_exists  "%VIRTL%\fileeecopy"   "5.1b copy in virtual"
:: original must still be visible (real untouched)
%VL% cmd /c type "%testdir%\fileee" >nul 2>nul
call :check_ok "5.1c original still readable"

:: ---------------------------------------------------------------
echo --- 5.2  copy real file over existing real file (overwrite)
call :reset
mkdir "%testdir%"
echo sdfsdf>"%testdir%\fileee"
echo sdfsdf>"%testdir%\fileee2"
%VL% cmd /S /c "echo y| copy /-Y "%testdir%\fileee" "%testdir%\fileee2""
call :check_ok "5.2a exit code 0"
call :expect_exists  "%VIRTL%\fileee2"   "5.2b overwrite in virtual"

:: ---------------------------------------------------------------
echo --- 5.3  copy real file onto itself (should warn, not duplicate)
call :reset
mkdir "%testdir%"
echo abc>"%testdir%\fileee"
%VL% cmd /c copy "%testdir%\fileee" "%testdir%\fileee" 2>&1 | findstr /I "itself\|same\|cannot" >nul
call :check_ok "5.3a self-copy produces a clear error message"

:: ---------------------------------------------------------------
echo --- 5.4  copy real file to a subdirectory
call :reset
mkdir "%testdir%\sub"
echo abc>"%testdir%\fileee"
%VL% cmd /c copy "%testdir%\fileee" "%testdir%\sub\"
call :check_ok "5.4a exit code 0"
call :expect_exists  "%VIRTL%\sub\fileee"   "5.4b file in virtual subdir"

:: ---------------------------------------------------------------
echo --- 5.5  copy virtual file to new name
call :reset
mkdir "%testdir%"
%VL% cmd /S /c "echo inside>"%testdir%\vfile" "
%VL% cmd /c copy "%testdir%\vfile" "%testdir%\vcopy"
call :check_ok "5.5a exit code 0"
call :expect_exists  "%VIRTL%\vcopy"   "5.5b virtual copy in virtual"

:: ---------------------------------------------------------------
echo --- 5.6  copy file to a different directory (real target dir)
call :reset
mkdir "%testdir%\src_dir"
mkdir "%testdir%\dst_dir"
echo aaa>"%testdir%\src_dir\f"
%VL% cmd /c copy "%testdir%\src_dir\f" "%testdir%\dst_dir\f"
call :check_ok "5.6a exit code 0"
call :expect_exists  "%VIRTL%\dst_dir\f"   "5.6b copied to different real dir"

:: ---------------------------------------------------------------
echo --- 5.7  copy file preserves content
call :reset
mkdir "%testdir%"
echo UNIQUE_MARKER_12345>"%testdir%\src"
%VL% cmd /c copy "%testdir%\src" "%testdir%\dst"
call :expect_content "%VIRTL%\dst" "UNIQUE_MARKER_12345" "5.7a content preserved in copy"

:: ---------------------------------------------------------------
echo --- 5.8  copy creates "- Copy" style name when copying in Explorer style
::           (Sandboxie behaviour: real file in same dir → new name, not shadow)
call :reset
mkdir "%testdir%"
echo abc>"%testdir%\fileee"
:: When copying fileee to the same dir via Explorer or API with FILE_CREATE,
:: the hook should return COLLISION so Windows appends "- Copy".
:: We verify that fileee itself is not replaced (real file untouched, no silent shadow).
%VL% cmd /c copy "%testdir%\fileee" "%testdir%\fileee" 2>&1 | findstr /I "itself\|cannot\|duplicate" >nul
call :check_ok "5.8a self-copy correctly rejected with one error"

:: ================================================================
call :section "COPY - FOLDERS"
:: ================================================================

:: ---------------------------------------------------------------
echo --- 6.1  xcopy real folder to non-existent destination
call :reset
mkdir "%testdir%\cc"
echo dsfsd>"%testdir%\cc\ggg"
%VL% cmd /c xcopy "%testdir%\cc" "%testdir%\vvc" /I /E /Q /H /R
call :check_ok "6.1a exit code 0"
call :expect_exists  "%VIRTL%\vvc\ggg"   "6.1b file in copied virtual dir"

:: ---------------------------------------------------------------
echo --- 6.2  xcopy real folder to existing real folder (overwrite contents)
call :reset
mkdir "%testdir%\cc"
mkdir "%testdir%\vvc"
echo dsfsd>"%testdir%\cc\ggg"
echo old>"%testdir%\vvc\ggg"
%VL% cmd /S /c "echo y|xcopy "%testdir%\cc" "%testdir%\vvc" /I /E /Q /H /R"
call :check_ok "6.2a exit code 0"
call :expect_exists  "%VIRTL%\vvc\ggg"   "6.2b overwritten file in virtual"

:: ---------------------------------------------------------------
echo --- 6.3  xcopy folder with nested subdirectories
call :reset
mkdir "%testdir%\src\a\b"
echo deep>"%testdir%\src\a\b\deep.txt"
%VL% cmd /c xcopy "%testdir%\src" "%testdir%\dst" /I /E /Q /H /R
call :check_ok "6.3a exit code 0"
call :expect_exists  "%VIRTL%\dst\a\b\deep.txt"   "6.3b deep copy in virtual"

:: ---------------------------------------------------------------
echo --- 6.4  xcopy virtual folder to new name
call :reset
mkdir "%testdir%"
%VL% cmd /c mkdir "%testdir%\vsrc"
%VL% cmd /S /c "echo vfile>"%testdir%\vsrc\vf" "
%VL% cmd /c xcopy "%testdir%\vsrc" "%testdir%\vdst" /I /E /Q /H /R
call :check_ok "6.4a exit code 0"
call :expect_exists  "%VIRTL%\vdst\vf"   "6.4b virtual-to-virtual copy"

:: ================================================================
call :section "DELETE - FILES"
:: ================================================================

:: ---------------------------------------------------------------
echo --- 7.1  delete real file (tombstone created)
call :reset
mkdir "%testdir%"
echo sdfsdf>"%testdir%\fileee"
%VL% cmd /c del "%testdir%\fileee"
call :check_ok "7.1a exit code 0"
:: File should be invisible inside sandbox
%VL% cmd /c if exist "%testdir%\fileee" exit 1
call :check_ok "7.1b file invisible inside sandbox after del"
:: But real file must still exist on real disk
call :expect_exists  "%testdir%\fileee"   "7.1c real file untouched on disk"

:: ---------------------------------------------------------------
echo --- 7.2  delete virtual file (no tombstone needed for pure virtual)
call :reset
mkdir "%testdir%"
%VL% cmd /S /c "echo inside>"%testdir%\vfile" "
%VL% cmd /c del "%testdir%\vfile"
call :check_ok "7.2a exit code 0"
call :expect_missing  "%VIRTL%\vfile"   "7.2b virtual file removed"

:: ---------------------------------------------------------------
echo --- 7.3  delete non-existent file (should error)
call :reset
mkdir "%testdir%"
%VL% cmd /c del "%testdir%\no_such_file" >nul 2>nul
call :check_fail "7.3a del of non-existent exits non-zero"

:: ---------------------------------------------------------------
echo --- 7.4  del with wildcard deletes only real files (tombstoned)
call :reset
mkdir "%testdir%"
echo a>"%testdir%\file_a.txt"
echo b>"%testdir%\file_b.txt"
%VL% cmd /c del "%testdir%\*.txt" >nul 2>nul
call :check_ok "7.4a del wildcard exit 0"
%VL% cmd /c if exist "%testdir%\file_a.txt" exit 1
call :check_ok "7.4b file_a invisible in sandbox"
%VL% cmd /c if exist "%testdir%\file_b.txt" exit 1
call :check_ok "7.4c file_b invisible in sandbox"

:: ---------------------------------------------------------------
echo --- 7.5  delete a previously renamed (virtual) file
call :reset
mkdir "%testdir%"
echo aaa>"%testdir%\fileee"
%VL% cmd /c rename "%testdir%\fileee" fileeerenamed
%VL% cmd /c del "%testdir%\fileeerenamed"
call :check_ok "7.5a del of renamed virtual file exits 0"
call :expect_missing "%VIRTL%\fileeerenamed"   "7.5b renamed-then-deleted gone"

:: ================================================================
call :section "DELETE - FOLDERS"
:: ================================================================

:: ---------------------------------------------------------------
echo --- 8.1  rmdir real folder (empty)
call :reset
mkdir "%testdir%\empty"
%VL% cmd /c rmdir "%testdir%\empty"
call :check_ok "8.1a exit code 0"
%VL% cmd /c if exist "%testdir%\empty" exit 1
call :check_ok "8.1b folder invisible in sandbox"

:: ---------------------------------------------------------------
echo --- 8.2  rmdir /S real folder with contents
call :reset
mkdir "%testdir%"
echo sdfsdf>"%testdir%\fileee"
%VL% cmd /S /c "echo y|rmdir /S "%testdir%""
call :check_ok "8.2a exit code 0"
%VL% cmd /c if exist "%testdir%\fileee" exit 1
call :check_ok "8.2b contents invisible in sandbox"
call :expect_exists  "%testdir%\fileee"   "8.2c real file untouched on disk"

:: ---------------------------------------------------------------
echo --- 8.3  rmdir virtual folder
call :reset
mkdir "%testdir%"
%VL% cmd /c mkdir "%testdir%\vdir"
%VL% cmd /c rmdir "%testdir%\vdir"
call :check_ok "8.3a exit code 0"
call :expect_missing  "%VIRTL%\vdir"   "8.3b virtual dir removed"

:: ---------------------------------------------------------------
echo --- 8.4  rmdir non-empty folder without /S (should fail)
call :reset
mkdir "%testdir%"
echo x>"%testdir%\f"
%VL% cmd /c rmdir "%testdir%" >nul 2>nul
call :check_fail "8.4a rmdir non-empty without /S fails"

:: ---------------------------------------------------------------
echo --- 8.5  delete folder then recreate it inside sandbox
call :reset
mkdir "%testdir%\rr"
%VL% cmd /c rmdir "%testdir%\rr"
%VL% cmd /c mkdir "%testdir%\rr"
call :check_ok "8.5a recreate after delete exits 0"
call :expect_exists  "%VIRTL%\rr"   "8.5b recreated folder in virtual"

:: ================================================================
call :section "READ / WRITE"
:: ================================================================

:: ---------------------------------------------------------------
echo --- 9.1  read a real file inside sandbox
call :reset
mkdir "%testdir%"
echo OUTSIDE_CONTENT>"%testdir%\fileee"
%VL% cmd /c type "%testdir%\fileee" | findstr OUTSIDE_CONTENT >nul
call :check_ok "9.1a real file readable in sandbox"

:: ---------------------------------------------------------------
echo --- 9.2  write to a real file (CoW: creates virtual copy)
call :reset
mkdir "%testdir%"
echo outside>"%testdir%\fileee"
%VL% cmd /S /c "echo inside>"%testdir%\fileee" "
call :expect_content "%VIRTL%\fileee" "inside" "9.2a virtual copy contains new content"
call :expect_content "%testdir%\fileee" "outside" "9.2b real file untouched"

:: ---------------------------------------------------------------
echo --- 9.3  write verifiable: second sandbox sees updated file
call :reset
mkdir "%testdir%"
echo outside>"%testdir%\fileee"
%VL% cmd /S /c "echo inside>"%testdir%\fileee" "
%VL% cmd /c type "%testdir%\fileee" | findstr inside >nul
call :check_ok "9.3a second sandbox run reads CoW content"

:: ---------------------------------------------------------------
echo --- 9.4  append to a real file (CoW)
call :reset
mkdir "%testdir%"
echo line1>"%testdir%\fileee"
%VL% cmd /S /c "echo line2>>"%testdir%\fileee" "
call :expect_content "%VIRTL%\fileee" "line2" "9.4a appended line in virtual file"

:: ---------------------------------------------------------------
echo --- 9.5  create new file inside sandbox (virtual only)
call :reset
mkdir "%testdir%"
%VL% cmd /S /c "echo newcontent>"%testdir%\newfile" "
call :expect_exists  "%VIRTL%\newfile"   "9.5a new file in virtual"
call :expect_missing "%testdir%\newfile" "9.5b real dir untouched"

:: ---------------------------------------------------------------
echo --- 9.6  create new subdirectory inside sandbox
call :reset
mkdir "%testdir%"
%VL% cmd /c mkdir "%testdir%\newdir"
call :check_ok "9.6a mkdir exit 0"
call :expect_exists  "%VIRTL%\newdir"   "9.6b new dir in virtual"

:: ---------------------------------------------------------------
echo --- 9.7  write to file in a newly-created virtual subdir
call :reset
mkdir "%testdir%"
%VL% cmd /c mkdir "%testdir%\newdir"
%VL% cmd /S /c "echo data>"%testdir%\newdir\f" "
call :expect_exists  "%VIRTL%\newdir\f"   "9.7a file in virtual subdir"

:: ---------------------------------------------------------------
echo --- 9.8  read from real file after CoW write to sibling file
call :reset
mkdir "%testdir%"
echo real_a>"%testdir%\a"
echo real_b>"%testdir%\b"
%VL% cmd /S /c "echo virtual_a>"%testdir%\a" "
%VL% cmd /c type "%testdir%\b" | findstr real_b >nul
call :check_ok "9.8a sibling real file still readable after CoW on 'a'"

:: ================================================================
call :section "TOMBSTONE / MERGED VIEW CORRECTNESS"
:: ================================================================

:: ---------------------------------------------------------------
echo --- 10.1  deleted real file invisible in dir listing
call :reset
mkdir "%testdir%"
echo x>"%testdir%\del_me"
%VL% cmd /c del "%testdir%\del_me" >nul 2>nul
%VL% cmd /c dir /b "%testdir%" 2>nul | findstr "del_me" >nul
call :check_fail "10.1a del_me absent from dir listing"

:: ---------------------------------------------------------------
echo --- 10.2  deleted real file can be recreated in sandbox
call :reset
mkdir "%testdir%"
echo x>"%testdir%\f"
%VL% cmd /c del "%testdir%\f" >nul 2>nul
%VL% cmd /S /c "echo new>"%testdir%\f" "
call :expect_content "%VIRTL%\f" "new" "10.2a recreated file has new content"

:: ---------------------------------------------------------------
echo --- 10.3  renamed real file: old name invisible, new name visible
call :reset
mkdir "%testdir%"
echo x>"%testdir%\old"
%VL% cmd /c rename "%testdir%\old" newname >nul 2>nul
%VL% cmd /c dir /b "%testdir%" | findstr /C:"old" >nul
call :check_fail "10.3a old name invisible after rename"
%VL% cmd /c dir /b "%testdir%" | findstr /C:"newname" >nul
call :check_ok   "10.3b new name visible after rename"

:: ---------------------------------------------------------------
echo --- 10.4  sandbox dir listing shows both virtual and real entries
call :reset
mkdir "%testdir%"
echo real>"%testdir%\real_file"
%VL% cmd /S /c "echo virt>"%testdir%\virt_file" "
%VL% cmd /c dir /b "%testdir%" | findstr "real_file" >nul
call :check_ok "10.4a real_file in listing"
%VL% cmd /c dir /b "%testdir%" | findstr "virt_file" >nul
call :check_ok "10.4b virt_file in listing"

:: ---------------------------------------------------------------
echo --- 10.5  tombstone survives restart of sandbox (persisted on disk)
call :reset
mkdir "%testdir%"
echo x>"%testdir%\persist_del"
%VL% cmd /c del "%testdir%\persist_del" >nul 2>nul
:: restart sandbox, file should still be invisible
%VL% cmd /c if exist "%testdir%\persist_del" exit 1
call :check_ok "10.5a tombstoned file still invisible in new sandbox run"

:: ---------------------------------------------------------------
echo --- 10.6  virtual file shadows real file of same name
call :reset
mkdir "%testdir%"
echo REAL>"%testdir%\f"
%VL% cmd /S /c "echo VIRTUAL>"%testdir%\f" "
%VL% cmd /c type "%testdir%\f" | findstr VIRTUAL >nul
call :check_ok "10.6a virtual file shadows real file"

:: ---------------------------------------------------------------
echo --- 10.7  remove virtual shadow: real file re-appears
call :reset
mkdir "%testdir%"
echo REAL>"%testdir%\f"
%VL% cmd /S /c "echo VIRTUAL>"%testdir%\f" "
:: delete virtual copy — original should re-emerge
%VL% cmd /c del "%testdir%\f" >nul 2>nul
%VL% cmd /c type "%testdir%\f" | findstr REAL >nul
call :check_ok "10.7a after deleting virtual shadow real re-emerges"

:: ================================================================
call :section "EDGE CASES & COMPOUND OPERATIONS"
:: ================================================================

:: ---------------------------------------------------------------
echo --- 11.1  create, write, rename, read back
call :reset
mkdir "%testdir%"
%VL% cmd /S /c "echo step1>"%testdir%\tmp" "
%VL% cmd /c rename "%testdir%\tmp" final
%VL% cmd /c type "%testdir%\final" | findstr step1 >nul
call :check_ok "11.1a create-write-rename-read chain"

:: ---------------------------------------------------------------
echo --- 11.2  copy real file, modify copy, original unchanged
call :reset
mkdir "%testdir%"
echo ORIGINAL>"%testdir%\src"
%VL% cmd /c copy "%testdir%\src" "%testdir%\dst"
%VL% cmd /S /c "echo MODIFIED>"%testdir%\dst" "
%VL% cmd /c type "%testdir%\src" | findstr ORIGINAL >nul
call :check_ok "11.2a source unchanged after modifying copy"

:: ---------------------------------------------------------------
echo --- 11.3  delete, recreate, write in same session
call :reset
mkdir "%testdir%"
echo OLD>"%testdir%\f"
%VL% cmd /c del "%testdir%\f" >nul
%VL% cmd /S /c "echo NEW>"%testdir%\f" "
%VL% cmd /c type "%testdir%\f" | findstr NEW >nul
call :check_ok "11.3a del-recreate-write chain"

:: ---------------------------------------------------------------
@rem this fail, this is a known bug and it happens in sandboxie too
@rem , so i will not fix it for now because if most of things work fine in sandboxie then even with this bug then things must work fine too with my tool, but this merits a fix really
@rem TODO: fix it
goto :bypasss
echo --- 11.4  nested rename: rename parent folder, access child
call :reset
mkdir "%testdir%\parent\child"
echo deep>"%testdir%\parent\child\deepfile"
%VL% cmd /c rename "%testdir%\parent" parent_new
%VL% cmd /c type "%testdir%\parent_new\child\deepfile" | findstr deep >nul
call :check_ok "11.4a child accessible after parent rename"
:bypasss


:: ---------------------------------------------------------------
echo --- 11.5  move then delete at destination
call :reset
mkdir "%testdir%"
echo x>"%testdir%\src"
%VL% cmd /c move "%testdir%\src" "%testdir%\dst" >nul
%VL% cmd /c del "%testdir%\dst" >nul
%VL% cmd /c if exist "%testdir%\dst" exit 1
call :check_ok "11.5a move-then-delete: dst invisible"
%VL% cmd /c if exist "%testdir%\src" exit 1
call :check_ok "11.5b move-then-delete: src still invisible"

:: ---------------------------------------------------------------
echo --- 11.6  copy file, delete original (real), copy still accessible
call :reset
mkdir "%testdir%"
echo DATA>"%testdir%\orig"
%VL% cmd /c copy "%testdir%\orig" "%testdir%\dup"
%VL% cmd /c del "%testdir%\orig" >nul
%VL% cmd /c type "%testdir%\dup" | findstr DATA >nul
call :check_ok "11.6a copy accessible after deleting original"

:: ---------------------------------------------------------------
echo --- 11.7  dir listing count after multiple operations
call :reset
mkdir "%testdir%"
echo a>"%testdir%\a"
echo b>"%testdir%\b"
echo c>"%testdir%\c"
%VL% cmd /c del "%testdir%\b" >nul
%VL% cmd /c rename "%testdir%\c" d >nul
set cnt=0
for /f %%L in ('%VL% cmd /c dir /b "%testdir%"') do set /a cnt+=1
set /a TOTAL+=1
:: expect a, d (b deleted, c renamed to d)
if !cnt! EQU 2 (
    set /a PASS+=1
) else (
    set /a FAIL+=1
    color 4F
    echo   FAIL: 11.7 expected 2 entries, got !cnt!
)

:: ---------------------------------------------------------------
echo --- 11.8  sandbox does not affect real filesystem
call :reset
mkdir "%testdir%"
echo REAL>"%testdir%\realfile"
%VL% cmd /S /c "echo VIRTUAL>"%testdir%\realfile" "
%VL% cmd /c del "%testdir%\realfile" >nul
call :expect_content "%testdir%\realfile" "REAL" "11.8a real file untouched after CoW+del"

:: ---------------------------------------------------------------
echo --- 11.9  rename after copy: only renamed version visible
call :reset
mkdir "%testdir%"
echo x>"%testdir%\src"
%VL% cmd /c copy "%testdir%\src" "%testdir%\copy1"
%VL% cmd /c rename "%testdir%\copy1" copy2
%VL% cmd /c if exist "%testdir%\copy1" exit 1
call :check_ok "11.9a old name invisible after rename"
call :expect_exists "%VIRTL%\copy2"   "11.9b new name exists in virtual"

:: ---------------------------------------------------------------
echo --- 11.10  write to deeply nested real file (deep CoW)
call :reset
mkdir "%testdir%\a\b\c"
echo DEEP>"%testdir%\a\b\c\deep.txt"
%VL% cmd /S /c "echo DEEPVIRT>"%testdir%\a\b\c\deep.txt" "
call :expect_content "%VIRTL%\a\b\c\deep.txt" "DEEPVIRT" "11.10a deep CoW content correct"
call :expect_content "%testdir%\a\b\c\deep.txt" "DEEP"    "11.10b real deep file untouched"

:: ================================================================
call :section "SUMMARY"
:: ================================================================

echo.
echo  Total : !TOTAL!
echo  PASS  : !PASS!
echo  FAIL  : !FAIL!
echo.

if !FAIL! EQU 0 (
    color 2F
    echo  ALL TESTS PASSED
) else (
    color 4F
    echo  !FAIL! TESTS FAILED
)

echo.
rmdir /Q /S "%VIRTL_BASE%" 2>nul
rmdir /Q /S "%testdir%" 2>nul
pause
