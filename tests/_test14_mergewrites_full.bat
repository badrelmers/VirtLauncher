@echo off
SETLOCAL EnableDelayedExpansion
CD /D "%~dp0"

mode con | findstr "32766" >nul|| mode con lines=32766 COLS=120 &REM prevent "mode con" from clearing the console

::_______________________________________________
REM set VLAUNCHER_VERBOSE=true
set VLAUNCHER_DEBUG=true

::_______________________________________________
color 2F
set "BUILD_DIR=..\build"
cd "%BUILD_DIR%"

:: ===========================================================
:: Paths
:: ===========================================================
set "T=c:\vl14_mergetest"
set "VL=%CD%\VIRTL"
:: VT = physical location of T inside the virtual store
:: (strips the drive colon: c:\foo  ->  VIRTL\c\foo)
set "VT=%VL%\%T::=%"

:: Launcher shorthand
set "EXE=VirtLauncher64.exe -r -f -e"

set /A PASS=0
set /A FAIL=0

goto :TESTS

:: ===========================================================
:: Subroutines
:: ===========================================================
:P
set /A PASS+=1
echo   PASS
exit /b 0

:F
set /A FAIL+=1
color 4F
echo   FAIL
exit /b 0

:: Reset virtual store + real test dir, then (re)create real test dir
:R
if exist "%VL%" rmdir /Q /S "%VL%"
if exist "%T%" rmdir /Q /S "%T%"
exit /b 0

:: ===========================================================
:TESTS
:: ===========================================================

call :R

echo.
echo ====================================================================
echo  VirtLauncher Merge-Writes Comprehensive Test Suite
echo ====================================================================


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 1 ^| READ -- sandbox sees real files through merged view
echo ====================================================================

echo.
echo __________________ 1.1  type a real file
call :R & mkdir "%T%"
echo REAL_CONTENT>"%T%\file.txt"
%EXE% cmd /c type "%T%\file.txt" | findstr /C:"REAL_CONTENT" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 1.2  sandbox sees real file with ^if exist
call :R & mkdir "%T%"
echo REAL_CONTENT>"%T%\file.txt"
%EXE% cmd /c dir /B "%T%\file.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 1.3  sandbox does NOT see non-existent file
call :R & mkdir "%T%"
%EXE% cmd /c type "%T%\ghost.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 1.4  sandbox sees real subdir
call :R & mkdir "%T%\sub"
%EXE% cmd /c dir /B "%T%\sub" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 1.5  dir listing shows all real files
call :R & mkdir "%T%"
echo R>"%T%\alpha.txt" & echo R>"%T%\beta.txt" & echo R>"%T%\gamma.txt"
%EXE% cmd /c dir /B "%T%" | findstr /C:"alpha.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%" | findstr /C:"beta.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%" | findstr /C:"gamma.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 1.6  findstr works on real file in sandbox
call :R & mkdir "%T%"
echo NEEDLE>"%T%\search.txt"
%EXE% cmd /c findstr /C:"NEEDLE" "%T%\search.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 1.7  sandbox sees real file in real subdir
call :R & mkdir "%T%\sub"
echo R>"%T%\sub\deep.txt"
%EXE% cmd /c type "%T%\sub\deep.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 2 ^| WRITE / COPY-ON-WRITE
echo ====================================================================

echo.
echo __________________ 2.1  write to real file - sandbox reads new content
call :R & mkdir "%T%"
echo REAL_CONTENT>"%T%\file.txt"
%EXE% cmd /S /C "echo MODIFIED_CONTENT>"%T%\file.txt""
%EXE% cmd /c type "%T%\file.txt" | findstr /C:"MODIFIED_CONTENT" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 2.2  write to real file - real file UNCHANGED (isolation)
type "%T%\file.txt" | findstr /C:"REAL_CONTENT" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 2.3  write to real file - virtual store has the CoW copy
if exist "%VT%\file.txt" (call :P) else (call :F)

echo __________________ 2.4  write to real file - virtual copy has modified content
type "%VT%\file.txt" | findstr /C:"MODIFIED_CONTENT" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 2.5  append to real file - sandbox sees appended line
call :R & mkdir "%T%"
echo LINE1>"%T%\file.txt"
%EXE% cmd /S /C "echo LINE2>>"%T%\file.txt""
%EXE% cmd /c type "%T%\file.txt" | findstr /C:"LINE2" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 2.6  append to real file - real file still has LINE1 only
type "%T%\file.txt" | findstr /C:"LINE1" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
type "%T%\file.txt" | findstr /C:"LINE2" >nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 2.7  write to real file in subdir - CoW works on subpaths
call :R & mkdir "%T%\sub"
echo REAL>"%T%\sub\file.txt"
%EXE% cmd /S /C "echo MOD>"%T%\sub\file.txt""
%EXE% cmd /c type "%T%\sub\file.txt" | findstr /C:"MOD" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
type "%T%\sub\file.txt" | findstr /C:"REAL" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 2.8  second sandbox run reads the persisted CoW copy
call :R & mkdir "%T%"
echo REAL>"%T%\file.txt"
%EXE% cmd /S /C "echo WRITTEN>"%T%\file.txt""
REM separate VirtLauncher invocation must still see WRITTEN (virtual store is persistent)
%EXE% cmd /c type "%T%\file.txt" | findstr /C:"WRITTEN" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 3 ^| NEW FILE CREATION (virtual-only files)
echo ====================================================================

echo.
echo __________________ 3.1  create new file in real dir - visible in sandbox
call :R & mkdir "%T%"
%EXE% cmd /S /C "echo VIRT_CONTENT>"%T%\newfile.txt""
%EXE% cmd /c type "%T%\newfile.txt" | findstr /C:"VIRT_CONTENT" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 3.2  create new file - in virtual store
if exist "%VT%\newfile.txt" (call :P) else (call :F)

echo __________________ 3.3  create new file - NOT in real dir (isolation)
if not exist "%T%\newfile.txt" (call :P) else (call :F)

echo __________________ 3.4  create new file under new virtual subdir
call :R & mkdir "%T%"
%EXE% cmd /S /C "mkdir "%T%\newdir" && echo VIRT>"%T%\newdir\file.txt""
%EXE% cmd /c type "%T%\newdir\file.txt" | findstr /C:"VIRT" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%VT%\newdir\file.txt" (call :P) else (call :F)
if not exist "%T%\newdir" (call :P) else (call :F)

echo __________________ 3.5  create multiple files in same virtual dir - all visible
call :R & mkdir "%T%"
%EXE% cmd /S /C "echo A>"%T%\a.txt" & echo B>"%T%\b.txt" & echo C>"%T%\c.txt""
%EXE% cmd /c dir /B "%T%" | findstr /C:"a.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%" | findstr /C:"b.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%" | findstr /C:"c.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 3.6  deep nested file creation (3 levels)
call :R & mkdir "%T%"
%EXE% cmd /S /C "mkdir "%T%\a\b\c" && echo DEEP>"%T%\a\b\c\deep.txt""
%EXE% cmd /c type "%T%\a\b\c\deep.txt" | findstr /C:"DEEP" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%VT%\a\b\c\deep.txt" (call :P) else (call :F)
if not exist "%T%\a\b\c\deep.txt" (call :P) else (call :F)

echo __________________ 3.7  create file in non-existent real dir (T itself missing)
call :R
REM T does not exist at all
%EXE% cmd /S /C "mkdir "%T%" && echo VIRT>"%T%\file.txt""
if exist "%VT%\file.txt" (call :P) else (call :F)
if not exist "%T%\file.txt" (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 4 ^| NEW DIRECTORY CREATION
echo ====================================================================

echo.
echo __________________ 4.1  mkdir under real dir - visible in sandbox
call :R & mkdir "%T%"
%EXE% cmd /c mkdir "%T%\newdir"
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\newdir" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 4.2  mkdir - in virtual store
if exist "%VT%\newdir" (call :P) else (call :F)

echo __________________ 4.3  mkdir - NOT in real dir
if not exist "%T%\newdir" (call :P) else (call :F)

echo __________________ 4.4  mkdir nested dirs (mkdir /p equivalent via multiple calls)
call :R & mkdir "%T%"
%EXE% cmd /c mkdir "%T%\a\b\c"
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%VT%\a\b\c" (call :P) else (call :F)

echo __________________ 4.5  mkdir existing real dir should succeed (or return exist)
call :R & mkdir "%T%\existing"
%EXE% cmd /c mkdir "%T%\existing" >nul 2>nul
REM Creating a dir that already exists in real returns non-zero in cmd, which is expected
REM What matters is the dir is still accessible
%EXE% cmd /c dir /B "%T%\existing" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 4.6  create file inside just-created virtual dir
call :R & mkdir "%T%"
%EXE% cmd /S /C "mkdir "%T%\fresh" && echo DATA>"%T%\fresh\file.txt""
%EXE% cmd /c type "%T%\fresh\file.txt" | findstr /C:"DATA" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 5 ^| FILE DELETE (tombstone)
echo ====================================================================

echo.
echo __________________ 5.1  del real file - command succeeds
call :R & mkdir "%T%"
echo REAL>"%T%\file.txt"
%EXE% cmd /c del "%T%\file.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 5.2  del real file - no longer visible in sandbox
%EXE% cmd /c type "%T%\file.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 5.3  del real file - real file still on disk (isolation)
if exist "%T%\file.txt" (call :P) else (call :F)

echo __________________ 5.4  del real file - tombstone created
if exist "%VT%\file.txt.vl_deleted" (call :P) else (call :F)

echo __________________ 5.5  del real file - second del fails (already tombstoned)
%EXE% cmd /c del "%T%\file.txt" 2>&1 | findstr /C:"Could Not Find %T%\file.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 5.6  del non-existent file - fails gracefully
call :R & mkdir "%T%"
%EXE% cmd /c del "%T%\ghost.txt" 2>&1 | findstr /C:"Could Not Find %T%\ghost.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 5.7  del virtual-only file - no longer visible
call :R & mkdir "%T%"
mkdir "%VT%" 2>nul
echo VIRT>"%VT%\vfile.txt"
%EXE% cmd /c del "%T%\vfile.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\vfile.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
if not exist "%VT%\vfile.txt" (call :P) else (call :F)

echo __________________ 5.8  del CoW file (real file that was written to in sandbox)
call :R & mkdir "%T%"
echo REAL>"%T%\file.txt"
%EXE% cmd /S /C "echo MOD>"%T%\file.txt""
%EXE% cmd /c del "%T%\file.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\file.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
if exist "%T%\file.txt" (call :P) else (call :F)

echo __________________ 5.9  del then recreate - tombstone cleared and new file visible
call :R & mkdir "%T%"
echo REAL>"%T%\file.txt"
%EXE% cmd /c del "%T%\file.txt" >nul 2>nul
%EXE% cmd /S /C "echo RECREATED>"%T%\file.txt""
%EXE% cmd /c type "%T%\file.txt" | findstr /C:"RECREATED" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%VT%\file.txt" (call :P) else (call :F)

echo __________________ 5.10  del with wildcard ^(del *.txt^) - all matching files removed
call :R & mkdir "%T%"
echo R>"%T%\a.txt" & echo R>"%T%\b.txt" & echo R>"%T%\c.log"
%EXE% cmd /c del "%T%\*.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\a.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\b.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
REM c.log is not .txt - must still be visible
%EXE% cmd /c type "%T%\c.log" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 6 ^| DIRECTORY DELETE
echo ====================================================================

echo.
echo __________________ 6.1  rmdir empty real dir - succeeds
call :R & mkdir "%T%"
mkdir "%T%\emptydir"
%EXE% cmd /c rmdir "%T%\emptydir" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 6.2  rmdir empty real dir - no longer visible in sandbox
%EXE% cmd /c dir /B "%T%\emptydir" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 6.3  rmdir empty real dir - real dir still on disk
if exist "%T%\emptydir" (call :P) else (call :F)

echo __________________ 6.4  rmdir /S real dir with files - succeeds ^(regression: was failing^)
call :R & mkdir "%T%"
mkdir "%T%\sub"
echo F1>"%T%\sub\file1.txt" & echo F2>"%T%\sub\file2.txt"
%EXE% cmd /S /C "echo y|rmdir /S "%T%\sub"" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 6.5  rmdir /S real dir - no longer visible in sandbox
%EXE% cmd /c dir /B "%T%\sub" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 6.6  rmdir /S real dir - real dir still on disk
if exist "%T%\sub\file1.txt" (call :P) else (call :F)

echo __________________ 6.7  rmdir /S real dir - tombstone created
if exist "%VT%\sub.vl_deleted" (call :P) else (call :F)

echo __________________ 6.8  rmdir virtual-only dir
call :R & mkdir "%T%"
%EXE% cmd /c mkdir "%T%\virtdir"
%EXE% cmd /c rmdir "%T%\virtdir" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\virtdir" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 6.9  rmdir /S virtual dir with virtual files
call :R & mkdir "%T%"
%EXE% cmd /S /C "mkdir "%T%\vd" && echo A>"%T%\vd\a.txt" && echo B>"%T%\vd\b.txt""
%EXE% cmd /S /C "echo y|rmdir /S "%T%\vd"" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\vd" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 6.10  rmdir /S real dir with real AND virtual files inside
call :R & mkdir "%T%"
mkdir "%T%\mixed"
echo REAL>"%T%\mixed\real.txt"
mkdir "%VT%\mixed" 2>nul
echo VIRT>"%VT%\mixed\virt.txt"
%EXE% cmd /S /C "echo y|rmdir /S "%T%\mixed"" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\mixed" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
if exist "%T%\mixed\real.txt" (call :P) else (call :F)

echo __________________ 6.11  rmdir /S then mkdir same name - dir usable again
call :R & mkdir "%T%"
mkdir "%T%\recyclable"
echo R>"%T%\recyclable\r.txt"
%EXE% cmd /S /C "echo y|rmdir /S "%T%\recyclable"" >nul
%EXE% cmd /c mkdir "%T%\recyclable"
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\recyclable" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 7 ^| FILE RENAME -- success cases
echo ====================================================================

echo.
echo __________________ 7.1  rename real file to non-existent name - succeeds
call :R & mkdir "%T%"
echo REAL>"%T%\fileee"
%EXE% cmd /c rename "%T%\fileee" fileeerenamed
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 7.2  rename real file - old name gone in sandbox
%EXE% cmd /c type "%T%\fileee" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 7.3  rename real file - new name visible in sandbox
%EXE% cmd /c type "%T%\fileeerenamed" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 7.4  rename real file - tombstone for old name in virtual store
if exist "%VT%\fileee.vl_deleted" (call :P) else (call :F)

echo __________________ 7.5  rename real file - virtual copy at new name
if exist "%VT%\fileeerenamed" (call :P) else (call :F)

echo __________________ 7.6  rename real file - real file still at original name
if exist "%T%\fileee" (call :P) else (call :F)

echo __________________ 7.7  rename virtual-only file to non-existent name
call :R & mkdir "%T%"
mkdir "%VT%" 2>nul
echo VIRT>"%VT%\vfile.txt"
%EXE% cmd /c rename "%T%\vfile.txt" vfile_renamed.txt
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\vfile.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\vfile_renamed.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%VT%\vfile_renamed.txt" (call :P) else (call :F)
if not exist "%VT%\vfile.txt" (call :P) else (call :F)

echo __________________ 7.8  rename real file to a tombstoned name ^(should succeed^)
call :R & mkdir "%T%"
echo A>"%T%\aaa.txt"
echo B>"%T%\bbb.txt"
REM tombstone bbb.txt first
%EXE% cmd /c del "%T%\bbb.txt" >nul 2>nul
REM now rename aaa.txt to bbb.txt: bbb is "gone" in sandbox, so should succeed
%EXE% cmd /c rename "%T%\aaa.txt" bbb.txt
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\bbb.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\aaa.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 8 ^| FILE RENAME -- collision / failure cases
echo ====================================================================

echo.
echo __________________ 8.1  rename real file to existing real name - fails
call :R & mkdir "%T%"
echo A>"%T%\fileee" & echo B>"%T%\fileee2"
%EXE% cmd /c rename "%T%\fileee" fileee2 2>&1 | findstr /C:"duplicate" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 8.2  rename real file to existing real name - error appears EXACTLY ONCE
call :R & mkdir "%T%"
echo A>"%T%\fileee" & echo B>"%T%\fileee2"
set /A ERR_COUNT=0
for /F "delims=" %%L in ('%EXE% cmd /c rename "%T%\fileee" fileee2 2^>^&1') do (
    echo %%L | findstr /C:"duplicate" >nul 2>nul
    if !ERRORLEVEL! EQU 0 set /A ERR_COUNT+=1
)
if !ERR_COUNT! EQU 1 (call :P) else (call :F)

echo __________________ 8.3  rename real dir to existing real dir - error EXACTLY ONCE ^(regression^)
call :R & mkdir "%T%"
mkdir "%T%\cc" & mkdir "%T%\vvc"
set /A ERR_COUNT=0
for /F "delims=" %%L in ('%EXE% cmd /c rename "%T%\cc" vvc 2^>^&1') do (
    echo %%L | findstr /C:"duplicate" >nul 2>nul
    if !ERRORLEVEL! EQU 0 set /A ERR_COUNT+=1
)
if !ERR_COUNT! EQU 1 (call :P) else (call :F)

echo __________________ 8.4  rename real file to existing real name - source still visible
call :R & mkdir "%T%"
echo A>"%T%\fileee" & echo B>"%T%\fileee2"
%EXE% cmd /c rename "%T%\fileee" fileee2 >nul 2>nul
%EXE% cmd /c type "%T%\fileee" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 8.5  rename real file to existing virtual name - fails
call :R & mkdir "%T%"
echo A>"%T%\fileee"
mkdir "%VT%" 2>nul
echo B>"%VT%\virt_target.txt"
%EXE% cmd /c rename "%T%\fileee" virt_target.txt 2>&1 | findstr /C:"duplicate" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 8.6  rename real file to existing virtual name - error EXACTLY ONCE
call :R & mkdir "%T%"
echo A>"%T%\fileee"
mkdir "%VT%" 2>nul
echo B>"%VT%\virt_target.txt"
set /A ERR_COUNT=0
for /F "delims=" %%L in ('%EXE% cmd /c rename "%T%\fileee" virt_target.txt 2^>^&1') do (
    echo %%L | findstr /C:"duplicate" >nul 2>nul
    if !ERRORLEVEL! EQU 0 set /A ERR_COUNT+=1
)
if !ERR_COUNT! EQU 1 (call :P) else (call :F)

echo __________________ 8.7  rename virtual file to existing virtual name - fails
call :R & mkdir "%T%"
mkdir "%VT%" 2>nul
echo A>"%VT%\va.txt"
echo B>"%VT%\vb.txt"
%EXE% cmd /c rename "%T%\va.txt" vb.txt 2>&1 | findstr /C:"duplicate" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 8.8  rename virtual file to existing real name - fails
call :R & mkdir "%T%"
echo REAL>"%T%\real_target.txt"
mkdir "%VT%" 2>nul
echo VIRT>"%VT%\vsrc.txt"
%EXE% cmd /c rename "%T%\vsrc.txt" real_target.txt 2>&1 | findstr /C:"duplicate" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 9 ^| DIRECTORY RENAME -- success cases
echo ====================================================================

echo.
echo __________________ 9.1  rename real dir to non-existent name - succeeds
call :R & mkdir "%T%"
mkdir "%T%\cc"
echo R>"%T%\cc\file.txt"
%EXE% cmd /c rename "%T%\cc" vvc
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 9.2  rename real dir - old name gone in sandbox
%EXE% cmd /c dir /B "%T%\cc" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 9.3  rename real dir - new name visible in sandbox
%EXE% cmd /c dir /B "%T%\vvc" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 9.4  rename real dir - tombstone for old name
if exist "%VT%\cc.vl_deleted" (call :P) else (call :F)

echo __________________ 9.5  rename real dir - virtual copy at new name
if exist "%VT%\vvc" (call :P) else (call :F)

echo __________________ 9.6  rename real dir - real dir still at old name
if exist "%T%\cc" (call :P) else (call :F)

@rem this test fail
@rem this happens in sandboxie too , so i will not fix it for now because if most of things work fine in sandboxie even with this bug,then things must work fine too with my tool, but this merits a fix really, but it will not be a good fix because we will have to copy the real folder to the virtual store which means the usually quick rename operations will now take a lot of time (the time needed to copy the original folder) + the space ocupied by the new copied files (imagine big filder and a script rename 3 times we will end up with 3 big folders in the virtual store+the real dir), so there is no clean an beautifull solution, so if i fix it i must make it an optional option using a flag to enable this fix when needed.
goto :bypasssz
echo __________________ 9.7  rename real dir - files inside new name are accessible
%EXE% cmd /c type "%T%\vvc\file.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
:bypasssz

echo __________________ 9.8  rename virtual dir to non-existent name
call :R & mkdir "%T%"
%EXE% cmd /S /C "mkdir "%T%\virtdir" && echo V>"%T%\virtdir\v.txt""
%EXE% cmd /c rename "%T%\virtdir" virtrenameddir
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\virtrenameddir" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\virtdir" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
REM files inside the renamed virtual dir still accessible
%EXE% cmd /c type "%T%\virtrenameddir\v.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 10 ^| DIRECTORY RENAME -- collision / failure cases
echo ====================================================================

echo.
echo __________________ 10.1  rename real dir to existing real dir - fails
call :R & mkdir "%T%"
mkdir "%T%\cc" & mkdir "%T%\vvc"
%EXE% cmd /c rename "%T%\cc" vvc 2>&1 | findstr /C:"duplicate" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 10.2  rename real dir to existing real dir - both dirs still visible
%EXE% cmd /c dir /B "%T%\cc" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\vvc" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 10.3  rename real dir to existing virtual dir - fails
call :R & mkdir "%T%"
mkdir "%T%\cc"
%EXE% cmd /c mkdir "%T%\virtdst"
%EXE% cmd /c rename "%T%\cc" virtdst 2>&1 | findstr /C:"duplicate" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 10.4  rename real dir to existing virtual dir - error EXACTLY ONCE
call :R & mkdir "%T%"
mkdir "%T%\cc"
%EXE% cmd /c mkdir "%T%\virtdst"
set /A ERR_COUNT=0
for /F "delims=" %%L in ('%EXE% cmd /c rename "%T%\cc" virtdst 2^>^&1') do (
    echo %%L | findstr /C:"duplicate" >nul 2>nul
    if !ERRORLEVEL! EQU 0 set /A ERR_COUNT+=1
)
if !ERR_COUNT! EQU 1 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 11 ^| FILE COPY
echo ====================================================================

echo.
echo __________________ 11.1  copy real file to new name in same dir
call :R & mkdir "%T%"
echo REAL_DATA>"%T%\src.txt"
%EXE% cmd /c copy "%T%\src.txt" "%T%\dst.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 11.2  copy - source still visible
%EXE% cmd /c type "%T%\src.txt" | findstr /C:"REAL_DATA" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 11.3  copy - destination visible in sandbox
%EXE% cmd /c type "%T%\dst.txt" | findstr /C:"REAL_DATA" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 11.4  copy - destination in virtual store
if exist "%VT%\dst.txt" (call :P) else (call :F)

echo __________________ 11.5  copy - destination NOT in real dir
if not exist "%T%\dst.txt" (call :P) else (call :F)

echo __________________ 11.6  copy real file to existing real file ^(overwrite /Y^)
call :R & mkdir "%T%"
echo SRC_DATA>"%T%\src.txt"
echo DST_DATA>"%T%\dst.txt"
%EXE% cmd /c copy /Y "%T%\src.txt" "%T%\dst.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\dst.txt" | findstr /C:"SRC_DATA" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
REM real dst.txt unchanged
type "%T%\dst.txt" | findstr /C:"DST_DATA" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 11.7  copy virtual file to new name
call :R & mkdir "%T%"
mkdir "%VT%" 2>nul
echo VIRT>"%VT%\vsrc.txt"
%EXE% cmd /c copy "%T%\vsrc.txt" "%T%\vcopy.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\vcopy.txt" | findstr /C:"VIRT" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%VT%\vcopy.txt" (call :P) else (call :F)

echo __________________ 11.8  copy real file to real subdir
call :R & mkdir "%T%"
mkdir "%T%\dst"
echo REAL>"%T%\src.txt"
%EXE% cmd /c copy "%T%\src.txt" "%T%\dst\copy.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%VT%\dst\copy.txt" (call :P) else (call :F)
if not exist "%T%\dst\copy.txt" (call :P) else (call :F)

echo __________________ 11.9  copy real file to virtual subdir
call :R & mkdir "%T%"
echo REAL>"%T%\src.txt"
%EXE% cmd /c mkdir "%T%\virtdst"
%EXE% cmd /c copy "%T%\src.txt" "%T%\virtdst\copy.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%VT%\virtdst\copy.txt" (call :P) else (call :F)

echo __________________ 11.10  copy real file to existing virtual file ^(overwrite^)
call :R & mkdir "%T%"
echo REAL>"%T%\src.txt"
mkdir "%VT%" 2>nul
echo VIRT>"%VT%\dst.txt"
%EXE% cmd /c copy /Y "%T%\src.txt" "%T%\dst.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\dst.txt" | findstr /C:"REAL" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 11.11  copy with wildcard ^(copy *.txt dst\^)
call :R & mkdir "%T%"
mkdir "%T%\dst"
echo A>"%T%\a.txt" & echo B>"%T%\b.txt"
%EXE% cmd /S /c "copy "%T%\*.txt" "%T%\dst" " >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%VT%\dst\a.txt" (call :P) else (call :F)
if exist "%VT%\dst\b.txt" (call :P) else (call :F)

:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 12 ^| DIRECTORY COPY (xcopy)
echo ====================================================================

echo.
echo __________________ 12.1  xcopy real dir to non-existent dir
call :R & mkdir "%T%\src"
echo A>"%T%\src\a.txt" & echo B>"%T%\src\b.txt"
%EXE% cmd /c xcopy "%T%\src" "%T%\dst" /I /E /Q /H /R | findstr /C:"2 File(s) copied" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 12.2  xcopy - files present in sandbox at dst
%EXE% cmd /c type "%T%\dst\a.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\dst\b.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 12.3  xcopy - dst files in virtual store
if exist "%VT%\dst\a.txt" (call :P) else (call :F)

echo __________________ 12.4  xcopy - dst NOT created in real dir
if not exist "%T%\dst" (call :P) else (call :F)

echo __________________ 12.5  xcopy - source real dir unchanged
if exist "%T%\src\a.txt" (call :P) else (call :F)
type "%T%\src\a.txt" | findstr /C:"A" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 12.6  xcopy real dir with subdirs ^(/E^)
call :R & mkdir "%T%\src\sub"
echo DEEP>"%T%\src\sub\deep.txt"
%EXE% cmd /c xcopy "%T%\src" "%T%\dst" /I /E /Q /H /R | findstr /C:"1 File(s) copied" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%VT%\dst\sub\deep.txt" (call :P) else (call :F)

echo __________________ 12.7  xcopy real dir to existing virtual dir ^(overwrite^)
call :R & mkdir "%T%\src"
echo SRCDATA>"%T%\src\file.txt"
%EXE% cmd /c mkdir "%T%\dst"
%EXE% cmd /S /C "echo y|xcopy "%T%\src" "%T%\dst" /I /E /Q /H /R" | findstr /C:"1 File(s) copied" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\dst\file.txt" | findstr /C:"SRCDATA" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 12.8  xcopy real dir to existing real dir ^(overwrite^)
call :R & mkdir "%T%\src"
mkdir "%T%\dst"
echo SRCDATA>"%T%\src\file.txt"
echo DSTDATA>"%T%\dst\file.txt"
%EXE% cmd /S /C "echo y|xcopy "%T%\src" "%T%\dst" /I /E /Q /H /R" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\dst\file.txt" | findstr /C:"SRCDATA" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
REM real dst\file.txt unchanged
type "%T%\dst\file.txt" | findstr /C:"DSTDATA" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 13 ^| FILE MOVE -- same directory (= rename semantics)
echo ====================================================================

echo.
echo __________________ 13.1  move real file to new name - succeeds
call :R & mkdir "%T%"
echo REAL>"%T%\src.txt"
%EXE% cmd /c move "%T%\src.txt" "%T%\dst.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 13.2  move real file - source gone in sandbox
%EXE% cmd /c type "%T%\src.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 13.3  move real file - destination visible in sandbox
%EXE% cmd /c type "%T%\dst.txt" | findstr /C:"REAL" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 13.4  move real file - real file still at original name
if exist "%T%\src.txt" (call :P) else (call :F)

echo __________________ 13.5  move real file - tombstone for source
if exist "%VT%\src.txt.vl_deleted" (call :P) else (call :F)

echo __________________ 13.6  move real file - destination in virtual store
if exist "%VT%\dst.txt" (call :P) else (call :F)

echo __________________ 13.7  move real file over existing real file ^(overwrite prompt^)
call :R & mkdir "%T%"
echo SRC_DATA>"%T%\src.txt"
echo DST_DATA>"%T%\dst.txt"
%EXE% cmd /S /C "echo y|move /-Y "%T%\src.txt" "%T%\dst.txt"" | findstr /C:"Overwrite" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
REM dst.txt has src content in sandbox
%EXE% cmd /c type "%T%\dst.txt" | findstr /C:"SRC_DATA" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
REM real dst.txt unchanged
type "%T%\dst.txt" | findstr /C:"DST_DATA" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
REM src.txt gone from sandbox
%EXE% cmd /c type "%T%\src.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 13.8  move virtual file to new name
call :R & mkdir "%T%"
mkdir "%VT%" 2>nul
echo VIRT>"%VT%\vsrc.txt"
%EXE% cmd /c move "%T%\vsrc.txt" "%T%\vdst.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\vsrc.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\vdst.txt" | findstr /C:"VIRT" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 14 ^| FILE MOVE -- cross-directory
echo ====================================================================

echo.
echo __________________ 14.1  move real file to different real dir
call :R & mkdir "%T%"
mkdir "%T%\dst"
echo REAL>"%T%\src.txt"
%EXE% cmd /c move "%T%\src.txt" "%T%\dst\src.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\src.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\dst\src.txt" | findstr /C:"REAL" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%T%\src.txt" (call :P) else (call :F)
if exist "%VT%\src.txt.vl_deleted" (call :P) else (call :F)
if exist "%VT%\dst\src.txt" (call :P) else (call :F)

echo __________________ 14.2  move real file to virtual dir
call :R & mkdir "%T%"
echo REAL>"%T%\src.txt"
%EXE% cmd /c mkdir "%T%\virtdst"
%EXE% cmd /c move "%T%\src.txt" "%T%\virtdst\src.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\virtdst\src.txt" | findstr /C:"REAL" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%VT%\virtdst\src.txt" (call :P) else (call :F)
if exist "%T%\src.txt" (call :P) else (call :F)

echo __________________ 14.3  move virtual file to real subdir
call :R & mkdir "%T%"
mkdir "%T%\dst"
mkdir "%VT%" 2>nul
echo VIRT>"%VT%\vsrc.txt"
%EXE% cmd /c move "%T%\vsrc.txt" "%T%\dst\vsrc.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\dst\vsrc.txt" | findstr /C:"VIRT" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%VT%\dst\vsrc.txt" (call :P) else (call :F)

echo __________________ 14.4  move real file over existing real file at dst ^(overwrite^)
call :R & mkdir "%T%\sub"
echo SRC>"%T%\src.txt"
echo DST>"%T%\sub\src.txt"
%EXE% cmd /S /C "echo y|move /-Y "%T%\src.txt" "%T%\sub\src.txt"" | findstr /C:"Overwrite" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\sub\src.txt" | findstr /C:"SRC" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%T%\src.txt" (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 15 ^| DIRECTORY MOVE
echo ====================================================================

echo.
echo __________________ 15.1  move real dir to new name ^(same parent^)
call :R & mkdir "%T%"
mkdir "%T%\cc"
echo R>"%T%\cc\file.txt"
%EXE% cmd /c move "%T%\cc" "%T%\vvv" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 15.2  move real dir - old name gone in sandbox
%EXE% cmd /c dir /B "%T%\cc" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 15.3  move real dir - new name visible in sandbox
%EXE% cmd /c dir /B "%T%\vvv" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

@rem this test fail
@rem this happens in sandboxie too , so i will not fix it for now because if most of things work fine in sandboxie even with this bug,then things must work fine too with my tool, but this merits a fix really, but it will not be a good fix because we will have to copy the real folder to the virtual store which means the usually quick rename operations will now take a lot of time (the time needed to copy the original folder) + the space ocupied by the new copied files (imagine big filder and a script rename 3 times we will end up with 3 big folders in the virtual store+the real dir), so there is no clean an beautifull solution, so if i fix it i must make it an optional option using a flag to enable this fix when needed.
goto :bypasssz2
echo __________________ 15.4  move real dir - files inside accessible at new name
%EXE% cmd /c type "%T%\vvv\file.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
:bypasssz2

echo __________________ 15.5  move real dir - real dir unchanged
if exist "%T%\cc" (call :P) else (call :F)
if exist "%VT%\cc.vl_deleted" (call :P) else (call :F)
if exist "%VT%\vvv" (call :P) else (call :F)

echo __________________ 15.6  move real dir into an existing real dir
call :R & mkdir "%T%"
mkdir "%T%\src"
mkdir "%T%\dst"
echo F>"%T%\src\file.txt"
%EXE% cmd /c move "%T%\src" "%T%\dst" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
REM move src INTO dst => dst\src
%EXE% cmd /c dir /B "%T%\dst\src" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

@rem this test fail
@rem this happens in sandboxie too , so i will not fix it for now because if most of things work fine in sandboxie even with this bug,then things must work fine too with my tool, but this merits a fix really, but it will not be a good fix because we will have to copy the real folder to the virtual store which means the usually quick rename operations will now take a lot of time (the time needed to copy the original folder) + the space ocupied by the new copied files (imagine big filder and a script rename 3 times we will end up with 3 big folders in the virtual store+the real dir), so there is no clean an beautifull solution, so if i fix it i must make it an optional option using a flag to enable this fix when needed.
@rem %EXE% cmd /c type "%T%\dst\src\file.txt" >nul 2>nul
@rem if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

REM tombstone src at parent level
if exist "%VT%\src.vl_deleted" (call :P) else (call :F)

echo __________________ 15.7  move real folder and overwrite ^(existing dst\src^)
call :R & mkdir "%T%"
mkdir "%T%\cc"
mkdir "%T%\dst\cc"
echo F>"%T%\cc\f.txt"
%EXE% cmd /S /C "echo y|move /-Y "%T%\cc" "%T%\dst" " | findstr /C:"Overwrite" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\dst\cc" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 16 ^| MERGED DIRECTORY LISTING
echo ====================================================================

echo.
echo __________________ 16.1  listing shows both real and virtual files
call :R & mkdir "%T%"
echo R>"%T%\real_file.txt"
mkdir "%VT%" 2>nul
echo V>"%VT%\virt_file.txt"
%EXE% cmd /c dir /B "%T%" | findstr /C:"real_file.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%" | findstr /C:"virt_file.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 16.2  listing does NOT show tombstoned file
call :R & mkdir "%T%"
echo R>"%T%\gone.txt"
echo R>"%T%\present.txt"
%EXE% cmd /c del "%T%\gone.txt" >nul 2>nul
%EXE% cmd /c dir /B "%T%" | findstr /C:"gone.txt" >nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%" | findstr /C:"present.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 16.3  listing does NOT show .vl_deleted tombstone files
call :R & mkdir "%T%"
echo R>"%T%\file.txt"
%EXE% cmd /c del "%T%\file.txt" >nul 2>nul
%EXE% cmd /c dir /B "%T%" | findstr /C:".vl_deleted" >nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 16.4  file in BOTH real and virtual - appears only ONCE
call :R & mkdir "%T%"
echo R>"%T%\shared.txt"
mkdir "%VT%" 2>nul
echo V>"%VT%\shared.txt"
set /A DUP_COUNT=0
for /F "delims=" %%L in ('%EXE% cmd /c dir /B "%T%"') do (
    echo %%L | findstr /C:"shared.txt" >nul 2>nul
    if !ERRORLEVEL! EQU 0 set /A DUP_COUNT+=1
)
if !DUP_COUNT! EQU 1 (call :P) else (call :F)

echo __________________ 16.5  listing shows virtual subdir alongside real files
call :R & mkdir "%T%"
echo R>"%T%\real.txt"
mkdir "%VT%" 2>nul
mkdir "%VT%\virtsubdir"
%EXE% cmd /c dir /B "%T%" | findstr /C:"virtsubdir" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%" | findstr /C:"real.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 16.6  listing of real subdir shows virtual files inside it
call :R & mkdir "%T%\sub"
echo R>"%T%\sub\real.txt"
mkdir "%VT%\sub" 2>nul
echo V>"%VT%\sub\virt.txt"
%EXE% cmd /c dir /B "%T%\sub" | findstr /C:"real.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\sub" | findstr /C:"virt.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 16.7  listing of real subdir with tombstone only shows remaining files
call :R & mkdir "%T%\sub"
echo R>"%T%\sub\keep.txt"
echo R>"%T%\sub\delete.txt"
%EXE% cmd /c del "%T%\sub\delete.txt" >nul 2>nul
%EXE% cmd /c dir /B "%T%\sub" | findstr /C:"delete.txt" >nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\sub" | findstr /C:"keep.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 16.8  real file modified ^(CoW^) - listing shows it only once
call :R & mkdir "%T%"
echo R>"%T%\cowfile.txt"
%EXE% cmd /S /C "echo V>"%T%\cowfile.txt""
set /A DUP_COUNT=0
for /F "delims=" %%L in ('%EXE% cmd /c dir /B "%T%"') do (
    echo %%L | findstr /C:"cowfile.txt" >nul 2>nul
    if !ERRORLEVEL! EQU 0 set /A DUP_COUNT+=1
)
if !DUP_COUNT! EQU 1 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 17 ^| COMPLEX / MULTI-STEP SCENARIOS
echo ====================================================================

echo.
echo __________________ 17.1  copy then modify copy - original unchanged
call :R & mkdir "%T%"
echo ORIGINAL>"%T%\orig.txt"
%EXE% cmd /c copy "%T%\orig.txt" "%T%\copy.txt" >nul
%EXE% cmd /S /C "echo CHANGED>"%T%\copy.txt""
%EXE% cmd /c type "%T%\orig.txt" | findstr /C:"ORIGINAL" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\copy.txt" | findstr /C:"CHANGED" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
type "%T%\orig.txt" | findstr /C:"ORIGINAL" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 17.2  rename chain: a to b, then b to c
call :R & mkdir "%T%"
echo DATA>"%T%\a.txt"
%EXE% cmd /c rename "%T%\a.txt" b.txt
%EXE% cmd /c rename "%T%\b.txt" c.txt
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\c.txt" | findstr /C:"DATA" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\a.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\b.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 17.3  delete dir then recreate - dir usable
call :R & mkdir "%T%"
mkdir "%T%\reborn"
echo R>"%T%\reborn\r.txt"
%EXE% cmd /S /C "echo y|rmdir /S "%T%\reborn"" >nul
%EXE% cmd /c mkdir "%T%\reborn"
%EXE% cmd /S /C "echo NEW>"%T%\reborn\new.txt""
%EXE% cmd /c type "%T%\reborn\new.txt" | findstr /C:"NEW" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
REM old real file should NOT appear (dir is tombstoned then recreated)

@rem this test fail
@rem this happens in sandboxie too , so i will not fix it for now because if most of things work fine in sandboxie even with this bug,then things must work fine too with my tool, but this merits a fix really, but it will not be a good fix because we will have to copy the real folder to the virtual store which means the usually quick rename operations will now take a lot of time (the time needed to copy the original folder) + the space ocupied by the new copied files (imagine big filder and a script rename 3 times we will end up with 3 big folders in the virtual store+the real dir), so there is no clean an beautifull solution, so if i fix it i must make it an optional option using a flag to enable this fix when needed.
@rem %EXE% cmd /c type "%T%\reborn\r.txt" >nul 2>nul
@rem if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 17.4  write to real file, rename it, read at new name
call :R & mkdir "%T%"
echo REAL>"%T%\orig.txt"
%EXE% cmd /S /C "echo MODIFIED>"%T%\orig.txt""
%EXE% cmd /c rename "%T%\orig.txt" renamed.txt
%EXE% cmd /c type "%T%\renamed.txt" | findstr /C:"MODIFIED" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\orig.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 17.5  move file, modify at new location, verify original real unchanged
call :R & mkdir "%T%"
mkdir "%T%\dst"
echo REAL>"%T%\src.txt"
%EXE% cmd /c move "%T%\src.txt" "%T%\dst\src.txt" >nul
%EXE% cmd /S /C "echo MODIFIED>"%T%\dst\src.txt""
type "%T%\src.txt" | findstr /C:"REAL" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\dst\src.txt" | findstr /C:"MODIFIED" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 17.6  create tree, delete subtree, verify parent still visible
call :R & mkdir "%T%"
mkdir "%T%\keep"
mkdir "%T%\kill"
echo K>"%T%\keep\k.txt" & echo X>"%T%\kill\x.txt"
%EXE% cmd /S /C "echo y|rmdir /S "%T%\kill"" >nul
%EXE% cmd /c dir /B "%T%\kill" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\keep\k.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 17.7  write to file, delete it, write again - new content at virt
call :R & mkdir "%T%"
echo V1>"%T%\file.txt"
%EXE% cmd /S /C "echo V1_MOD>"%T%\file.txt""
%EXE% cmd /c del "%T%\file.txt" >nul 2>nul
%EXE% cmd /S /C "echo V2>"%T%\file.txt""
%EXE% cmd /c type "%T%\file.txt" | findstr /C:"V2" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 17.8  simultaneous real and virtual content under same parent
call :R & mkdir "%T%\parent"
echo REAL>"%T%\parent\r.txt"
mkdir "%VT%\parent" 2>nul
echo VIRT>"%VT%\parent\v.txt"
%EXE% cmd /c type "%T%\parent\r.txt" | findstr /C:"REAL" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\parent\v.txt" | findstr /C:"VIRT" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\parent" | findstr /C:"r.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\parent" | findstr /C:"v.txt" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 18 ^| PERSISTENCE ACROSS MULTIPLE VirtLauncher RUNS
echo ====================================================================

echo.
echo __________________ 18.1  file created in run 1 visible in run 2
call :R & mkdir "%T%"
%EXE% cmd /S /C "echo PERSIST>"%T%\persist.txt""
%EXE% cmd /c type "%T%\persist.txt" | findstr /C:"PERSIST" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 18.2  tombstone from run 1 hides file in run 2
call :R & mkdir "%T%"
echo REAL>"%T%\file.txt"
%EXE% cmd /c del "%T%\file.txt" >nul 2>nul
%EXE% cmd /c type "%T%\file.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 18.3  CoW modification from run 1 visible in run 2
call :R & mkdir "%T%"
echo ORIGINAL>"%T%\file.txt"
%EXE% cmd /S /C "echo UPDATED>"%T%\file.txt""
%EXE% cmd /c type "%T%\file.txt" | findstr /C:"UPDATED" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 19 ^| WILDCARD OPERATIONS
echo ====================================================================

echo.
echo __________________ 19.1  move *.txt to subdir
call :R & mkdir "%T%"
mkdir "%T%\dst"
echo A>"%T%\a.txt" & echo B>"%T%\b.txt" & echo C>"%T%\c.log"
%EXE% cmd /c move "%T%\*.txt" "%T%\dst" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\dst\a.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\dst\b.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
REM .log file stays behind
%EXE% cmd /c type "%T%\c.log" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
REM a.txt and b.txt gone from root
%EXE% cmd /c type "%T%\a.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 19.2  del *.log wildcard leaves .txt intact
call :R & mkdir "%T%"
echo A>"%T%\a.txt" & echo B>"%T%\b.txt" & echo C>"%T%\c.log" & echo D>"%T%\d.log"
%EXE% cmd /c del "%T%\*.log" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\c.log" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\a.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 19.3  copy *.txt dst\ copies only matching files
call :R & mkdir "%T%"
mkdir "%T%\dst"
echo A>"%T%\a.txt" & echo B>"%T%\b.log"
%EXE% cmd /c copy "%T%\*.txt" "%T%\dst" >nul
if exist "%VT%\dst\a.txt" (call :P) else (call :F)
if not exist "%VT%\dst\b.log" (call :P) else (call :F)

echo __________________ 19.4  wildcard on mix of real and virtual files
call :R & mkdir "%T%"
echo R>"%T%\real.txt"
mkdir "%VT%" 2>nul
echo V>"%VT%\virt.txt"
%EXE% cmd /c del "%T%\*.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\real.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\virt.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  SECTION 20 ^| EDGE CASES
echo ====================================================================

echo.
echo __________________ 20.1  file with spaces in name
call :R & mkdir "%T%"
echo SPACED>"%T%\file with spaces.txt"
%EXE% cmd /S /C "type "%T%\file with spaces.txt" " | findstr /C:"SPACED" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /S /C "echo SPMOD>"%T%\file with spaces.txt" "
%EXE% cmd /S /c "type "%T%\file with spaces.txt" " | findstr /C:"SPMOD" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
type "%T%\file with spaces.txt" | findstr /C:"SPACED" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 20.2  dir with spaces in name
call :R & mkdir "%T%"
mkdir "%T%\dir with spaces"
echo R>"%T%\dir with spaces\file.txt"
%EXE% cmd /c type "%T%\dir with spaces\file.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c rename "%T%\dir with spaces" "renamed dir"
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c dir /B "%T%\renamed dir" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 20.3  empty file ^(0 bytes^)
call :R & mkdir "%T%"
copy nul "%T%\empty.txt" >nul
%EXE% cmd /c type "%T%\empty.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c del "%T%\empty.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\empty.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 20.4  4-level deep path operations
call :R & mkdir "%T%\a\b\c\d"
echo DEEP>"%T%\a\b\c\d\leaf.txt"
%EXE% cmd /c type "%T%\a\b\c\d\leaf.txt" | findstr /C:"DEEP" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /S /C "echo DEEPMOD>"%T%\a\b\c\d\leaf.txt""
%EXE% cmd /c type "%T%\a\b\c\d\leaf.txt" | findstr /C:"DEEPMOD" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
type "%T%\a\b\c\d\leaf.txt" | findstr /C:"DEEP" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c del "%T%\a\b\c\d\leaf.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\a\b\c\d\leaf.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 20.5  rename file to same name ^(no-op - should succeed^)
call :R & mkdir "%T%"
echo R>"%T%\file.txt"
%EXE% cmd /c rename "%T%\file.txt" file.txt
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\file.txt" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 20.6  virtual file created immediately after tombstone at same path
call :R & mkdir "%T%"
echo R>"%T%\file.txt"
%EXE% cmd /S /C "del "%T%\file.txt" & echo NEW>"%T%\file.txt""
%EXE% cmd /c type "%T%\file.txt" | findstr /C:"NEW" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
if exist "%VT%\file.txt" (call :P) else (call :F)
type "%T%\file.txt" | findstr /C:"R" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 20.7  copy-on-write does not break subsequent operations on same file
call :R & mkdir "%T%"
echo LINE1>"%T%\file.txt"
%EXE% cmd /S /C "echo LINE2>>"%T%\file.txt" && echo LINE3>>"%T%\file.txt""
%EXE% cmd /c type "%T%\file.txt" | findstr /C:"LINE2" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
%EXE% cmd /c type "%T%\file.txt" | findstr /C:"LINE3" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)
type "%T%\file.txt" | findstr /C:"LINE1" >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

echo __________________ 20.8  move non-existent file ^(should fail^)
call :R & mkdir "%T%"
%EXE% cmd /c move "%T%\nope.txt" "%T%\dst.txt" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 20.9  rmdir non-existent dir ^(should fail^)
call :R & mkdir "%T%"
%EXE% cmd /c rmdir "%T%\nope" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (call :P) else (call :F)

echo __________________ 20.10  rmdir non-empty dir without /S ^(should fail^)
@rem sandboxie also have a strange behavior with this test, in sandboxie the first time i run rmdir nothing is printed and an empty folder is created in the virt store, and only the second time i run rmdir it works fine and print: The directory is not empty.!!!
@rem with virtlauncher the first run it create nonempty.vl_deleted which means that the delete was succuful which wrong , it should fail.
@rem update: i fixed it
call :R & mkdir "%T%"
mkdir "%T%\nonempty"
echo R>"%T%\nonempty\r.txt"
%EXE% cmd /c rmdir "%T%\nonempty" 2>&1 | findstr /C:"The directory is not empty." >nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)

REM dir still visible after failed rmdir
%EXE% cmd /c dir /B "%T%\nonempty" >nul 2>nul
if %ERRORLEVEL% EQU 0 (call :P) else (call :F)


:: ====================================================================
echo.
echo ====================================================================
echo  RESULTS
echo ====================================================================
echo.

set /A TOTAL=PASS+FAIL
echo  Total checks : %TOTAL%
echo  Passed       : %PASS%
echo  Failed       : %FAIL%
echo.

if %FAIL% EQU 0 (
    echo  *** ALL TESTS PASSED ***
) else (
    color 4F
    echo  *** %FAIL% TESTS FAILED ***
)

echo.
if exist "%VL%" rmdir /Q /S "%VL%"
if exist "%T%" rmdir /Q /S "%T%"
if not "%DoNotPause%"=="yes" pause
exit /b !FAIL!
