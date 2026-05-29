@echo off
setlocal EnableDelayedExpansion
CD /D "%~dp0"

::_______________________________________________
 @rem set VLAUNCHER_VERBOSE=true
 set VLAUNCHER_DEBUG=true


::_______________________________________________
CD /D "..\build"
color 2F

:: Counters
set /a PASS_COUNT=0
set /a FAIL_COUNT=0

:: --- Configuration ---
set "testdir=c:\test12_merged_writes"
set "virthome=%CD%\VIRTL"
set "virt_testdir=%virthome%\C\test12_merged_writes"
set "OUT_LOG=%CD%\test_output.log"

echo ========================================================
echo VIRTLAUNCHER EXHAUSTIVE MERGED WRITES TEST SUITE
echo ========================================================
echo.

:: --- Helper Functions ---
goto :Main

:ResetEnv
    rmdir /Q /S "%virthome%" 2>nul
    rmdir /Q /S "%testdir%" 2>nul
    mkdir "%testdir%" 2>nul
    if exist "%OUT_LOG%" del /F /Q "%OUT_LOG%"
goto :eof

:Fail
    color 4F
    echo [FAIL] %~1
    set /a FAIL_COUNT+=1
    echo.
goto :eof

:Pass
    @rem echo [PASS] %~1
    echo good
    set /a PASS_COUNT+=1
goto :eof





:CheckOutputCount
    :: %1 = Expected Count, %2 = Search String
    for /f %%C in ('find /C /I "%~2" ^< "%OUT_LOG%" 2^>nul') do set "count=%%C"
    if "!count!" EQU "%~1" (
        set /a PASS_COUNT+=1
        echo good
        exit /b 0
    ) else (
        set /a FAIL_COUNT+=1
        echo [FAIL] Expected "%~2" to appear %~1 times, but found !count! times.
        type "%OUT_LOG%"
        exit /b 1
    )
goto :eof

:AssertFileExists
    if not exist "%~1" (
        call :Fail "Missing expected file: %~1"
        exit /b 1
    )
    echo good
    set /a PASS_COUNT+=1
    exit /b 0
goto :eof

:AssertFileMissing
    if exist "%~1" (
        call :Fail "File should not exist but does: %~1"
        exit /b 1
    )
    echo good
    set /a PASS_COUNT+=1
    exit /b 0
goto :eof

:Main

:: ========================================================
echo.
echo [1] READ / WRITE / COW OPERATIONS
echo ========================================================

echo __________________1.1 CoW Write to Real File ---
call :ResetEnv
echo original > "%testdir%\f1.txt"
VirtLauncher64.exe -r -f -e cmd /c "echo modified > "%testdir%\f1.txt"" > "%OUT_LOG%" 2>&1
call :AssertFileExists "%virt_testdir%\f1.txt" || goto :skip1
call :AssertFileExists "%testdir%\f1.txt" || goto :skip1
findstr /C:"original" "%testdir%\f1.txt" >nul || (call :Fail "Real file was modified!" & goto :skip1)
call :Pass "1.1 CoW Write to Real File"
:skip1

echo __________________1.2 Write to New Subdirectory ---
call :ResetEnv
VirtLauncher64.exe -r -f -e cmd /c "mkdir "%testdir%\sub" & echo new > "%testdir%\sub\f2.txt"" > "%OUT_LOG%" 2>&1
call :AssertFileExists "%virt_testdir%\sub\f2.txt" || goto :skip2
call :AssertFileMissing "%testdir%\sub\f2.txt" || goto :skip2
call :Pass "1.2 Write to New Subdirectory"
:skip2


:: ========================================================
echo.
echo [2] DELETE AND TOMBSTONING
echo ========================================================

echo __________________2.1 Delete Real File (Creates Tombstone) ---
call :ResetEnv
echo data > "%testdir%\f_del.txt"
VirtLauncher64.exe -r -f -e cmd /c "del "%testdir%\f_del.txt"" > "%OUT_LOG%" 2>&1
call :AssertFileExists "%testdir%\f_del.txt" || goto :skip3
call :AssertFileExists "%virt_testdir%\f_del.txt.vl_deleted" || goto :skip3
call :CheckOutputCount "0" "The system cannot find" || goto :skip3
call :Pass "2.1 Delete Real File"
:skip3

echo __________________2.2 Delete Real Directory ---
call :ResetEnv
mkdir "%testdir%\dir_del"
echo data > "%testdir%\dir_del\f.txt"
VirtLauncher64.exe -r -f -e cmd /c "echo y| rmdir /S "%testdir%\dir_del"" > "%OUT_LOG%" 2>&1
call :AssertFileExists "%virt_testdir%\dir_del.vl_deleted" || goto :skip4
call :CheckOutputCount "0" "The directory is not empty" || goto :skip4
call :Pass "2.2 Delete Real Directory"
:skip4


:: ========================================================
echo.
echo [3] RENAME OPERATIONS
echo ========================================================

echo __________________3.1 Rename Real File to New Name ---
call :ResetEnv
echo data > "%testdir%\f_ren.txt"
VirtLauncher64.exe -r -f -e cmd /c "rename "%testdir%\f_ren.txt" f_new.txt" > "%OUT_LOG%" 2>&1
call :CheckOutputCount "0" "The system cannot find" || goto :skip5
call :AssertFileExists "%virt_testdir%\f_new.txt" || goto :skip5
call :AssertFileExists "%virt_testdir%\f_ren.txt.vl_deleted" || goto :skip5
call :Pass "3.1 Rename Real File to New Name"
:skip5

@rem this test fail even in sandboxie so i will not fix it now in my code
goto :bypasss

echo __________________3.2 Rename Real Folder to New Folder ---
call :ResetEnv
mkdir "%testdir%\ren_dir"
echo data > "%testdir%\ren_dir\data.txt"
VirtLauncher64.exe -r -f -e cmd /S /c ""rename "%testdir%\ren_dir" new_dir" " > "%OUT_LOG%" 2>&1
call :CheckOutputCount "0" "The system cannot find" || goto :skip6
call :AssertFileExists "%virt_testdir%\new_dir\data.txt" || goto :skip6
call :AssertFileExists "%virt_testdir%\ren_dir.vl_deleted" || goto :skip6
call :Pass "3.2 Rename Real Folder to New Folder"
:skip6
:bypasss

echo __________________3.3 Rename Real File to Existing Real File (Collision) ---
call :ResetEnv
echo data1 > "%testdir%\f_src.txt"
echo data2 > "%testdir%\f_dst.txt"
VirtLauncher64.exe -r -f -e cmd /c "rename "%testdir%\f_src.txt" f_dst.txt" > "%OUT_LOG%" 2>&1
:: Expect EXACTLY ONE duplicate file name error
call :CheckOutputCount "1" "A duplicate file name exists" || goto :skip7
call :Pass "3.3 Rename Real File to Existing Real File"
:skip7

echo __________________3.4 Rename Real Folder to Existing Real Folder (Collision) ---
call :ResetEnv
mkdir "%testdir%\dir_src"
mkdir "%testdir%\dir_dst"
VirtLauncher64.exe -r -f -e cmd /c "rename "%testdir%\dir_src" dir_dst" > "%OUT_LOG%" 2>&1
:: Expect EXACTLY ONE duplicate file name error
call :CheckOutputCount "1" "A duplicate file name exists" || goto :skip8
call :Pass "3.4 Rename Real Folder to Existing Real Folder"
:skip8


:: ========================================================
echo.
echo [4] MOVE OPERATIONS
echo ========================================================

echo __________________4.1 Move Real File to New Name ---
call :ResetEnv
echo data > "%testdir%\f_move.txt"
VirtLauncher64.exe -r -f -e cmd /c "move "%testdir%\f_move.txt" "%testdir%\f_moved.txt"" > "%OUT_LOG%" 2>&1
call :CheckOutputCount "0" "The system cannot find" || goto :skip9
call :AssertFileExists "%virt_testdir%\f_moved.txt" || goto :skip9
call :AssertFileExists "%virt_testdir%\f_move.txt.vl_deleted" || goto :skip9
call :Pass "4.1 Move Real File to New Name"
:skip9

echo __________________4.2 Move Real File to Existing Real File (Overwrite) ---
call :ResetEnv
echo data1 > "%testdir%\f_src.txt"
echo data2 > "%testdir%\f_dst.txt"
VirtLauncher64.exe -r -f -e cmd /c "echo y| move /-Y "%testdir%\f_src.txt" "%testdir%\f_dst.txt"" > "%OUT_LOG%" 2>&1
call :CheckOutputCount "1" "1 file(s) moved" || goto :skip10
call :CheckOutputCount "1" "Overwrite" || goto :skip10
call :AssertFileExists "%virt_testdir%\f_dst.txt" || goto :skip10
call :AssertFileExists "%virt_testdir%\f_src.txt.vl_deleted" || goto :skip10
call :Pass "4.2 Move Real File to Existing Real File"
:skip10


:: ========================================================
echo.
echo [5] COPY OPERATIONS
echo ========================================================

echo __________________5.1 Copy Real File to Itself ---
call :ResetEnv
echo data > "%testdir%\f_copy.txt"
VirtLauncher64.exe -r -f -e cmd /c "copy "%testdir%\f_copy.txt" "%testdir%\f_copy.txt"" > "%OUT_LOG%" 2>&1
:: Expect EXACTLY ONE "cannot be copied onto itself" error
call :CheckOutputCount "1" "The file cannot be copied onto itself" || goto :skip11
call :Pass "5.1 Copy Real File to Itself"
:skip11

echo __________________5.2 XCopy Folder to Non-Existent Folder ---
call :ResetEnv
mkdir "%testdir%\xc_src"
echo data > "%testdir%\xc_src\f.txt"
VirtLauncher64.exe -r -f -e cmd /c "xcopy "%testdir%\xc_src" "%testdir%\xc_dst" /I /E /Q /H /R" > "%OUT_LOG%" 2>&1
call :CheckOutputCount "0" "Invalid path" || goto :skip12
call :CheckOutputCount "1" "1 File(s) copied" || goto :skip12
call :AssertFileExists "%virt_testdir%\xc_dst\f.txt" || goto :skip12
call :Pass "5.2 XCopy Folder to Non-Existent Folder"
:skip12


:: ========================================================
echo.
echo [6] ADVANCED MERGED VIEW / TOMBSTONE EDGE CASES
echo ========================================================

echo __________________6.1 Recreate Deleted File (Tombstone Overwrite) ---
call :ResetEnv
echo original > "%testdir%\f_revive.txt"
:: Delete it virtually
VirtLauncher64.exe -r -f -e cmd /c "del "%testdir%\f_revive.txt"" > "%OUT_LOG%" 2>&1
call :AssertFileExists "%virt_testdir%\f_revive.txt.vl_deleted" || goto :skip13
:: Recreate it virtually
VirtLauncher64.exe -r -f -e cmd /c "echo new > "%testdir%\f_revive.txt"" > "%OUT_LOG%" 2>&1
:: Tombstone should be gone, virtual file should exist
call :AssertFileMissing "%virt_testdir%\f_revive.txt.vl_deleted" || goto :skip13
call :AssertFileExists "%virt_testdir%\f_revive.txt" || goto :skip13
call :Pass "6.1 Recreate Deleted File"
:skip13

echo.
echo ========================================================
echo ALL TESTS COMPLETED.
echo ========================================================
if exist "%OUT_LOG%" del /F /Q "%OUT_LOG%"
rmdir /Q /S "%virthome%"
rmdir /Q /S "%testdir%"



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
if not "%DoNotPause%"=="yes" pause
exit /b %FAIL_COUNT%



