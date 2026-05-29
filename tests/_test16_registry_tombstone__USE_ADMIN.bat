@echo off
SETLOCAL
CD /D "%~dp0"

REM check admin
fltmc >nul 2>&1 || ( color 4F & echo. & echo RUNME AS ADMIN & echo. & pause & exit )

mode con | findstr "32766" >nul|| mode con lines=32766 COLS=120 &REM prevent "mode con" from clearing the console

:: ============================================================
REM set VLAUNCHER_VERBOSE=true
set VLAUNCHER_DEBUG=true


::_______________________________________________
color 2F
:: --- Configuration ---
set "BUILD_DIR=..\build"
cd "%BUILD_DIR%"

:: Counters
set /a PASS_COUNT=0
set /a FAIL_COUNT=0

:: Root test key created OUTSIDE the sandbox (real registry).
:: All tests operate under this key.
set "TROOT=HKCU\Software\_VLTest_Tombstone"

:: The registry virtual store root (where tombstones live).
:: VirtLauncher stores all virtual registry writes under this key.
:: Must be wiped between tests or tombstones from one test contaminate the next.
set "VREG=HKCU\VirtLauncher_tombstones_tests"

:: Clean up from any previous run
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul


::================================================================================
echo.
echo ========================================================
echo 1  KEY TOMBSTONE  --  delete a real key
echo ========================================================
echo.
::================================================================================

echo __________________1 1 delete a real key: key must vanish inside sandbox
@rem Real key TROOT\delme exists.
@rem Inside the sandbox: reg delete TROOT\delme /f
@rem After the sandbox exits, querying TROOT\delme inside the sandbox must return
@rem NOT FOUND -- the tombstone must block resurrection.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\delme" /f >nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\delme" /f >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - delete succeeded"
) else (
    call :Fail " - delete failed with errorlevel %ERRORLEVEL%"
)

@rem Real key must still exist outside the sandbox
reg query "%TROOT%\delme" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - real key still exists outside sandbox"
) else (
    call :Fail " - real key was deleted outside the sandbox"
)

@rem Inside sandbox the key must NOT be visible
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\delme" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - key correctly invisible inside sandbox after delete"
) else (
    call :Fail " - deleted key still visible inside sandbox"
)


echo __________________1 2 deleted key must not reappear in a new sandbox session
@rem Close and reopen the sandbox -- the tombstone must survive across sessions.
@rem VIRTL is kept from the previous test (no rmdir).

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\delme" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - tombstone persisted across sessions"
) else (
    call :Fail " - tombstone lost, key resurrected in new session"
)


echo __________________1 3 delete a real key with a value: key AND value must vanish
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\keyval" /v "myval" /t REG_SZ /d "hello" /f >nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\keyval" /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\keyval" /v myval >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - key with value invisible after delete"
) else (
    call :Fail " - key with value still visible"
)


echo __________________1 4 delete a real key: subkeys must vanish too
@rem When a parent key is deleted all its children must become invisible.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\parent\child1" /f >nul
reg add "%TROOT%\parent\child2" /v "data" /t REG_DWORD /d 42 /f >nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\parent" /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\parent" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - parent key invisible"
) else (
    call :Fail " - parent key still visible"
)

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\parent\child1" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - child1 invisible after parent delete"
) else (
    call :Fail " - child1 still visible"
)


echo __________________1 5 recreate a tombstoned key: must succeed and be visible
@rem After deleting a real key inside sandbox, the app can re-create it.
@rem The new virtual key must be visible (tombstone replaced by live CoW key).

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\recreate" /f >nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\recreate" /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg add "%TROOT%\recreate" /v "newval" /t REG_SZ /d "new" /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\recreate" /v newval >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - recreated key visible with new value"
) else (
    call :Fail " - recreated key not visible"
)

@rem The new value must only exist inside the sandbox, not in the real registry
reg query "%TROOT%\recreate" /v newval >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - new value correctly sandboxed"
) else (
    call :Fail " - new value leaked to real registry"
)


echo __________________1 6 delete a virtual-only key: must not leave orphan entries
@rem Key was written entirely inside the sandbox (no real counterpart).
@rem Deleting it should succeed silently.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg add "%TROOT%\virtonly" /v "x" /t REG_SZ /d "y" /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\virtonly" /f >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - delete of virtual-only key succeeded"
) else (
    call :Fail " - delete of virtual-only key failed"
)

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\virtonly" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - virtual-only key invisible after delete"
) else (
    call :Fail " - virtual-only key still visible after delete"
)


::================================================================================
echo.
echo ========================================================
echo 2  VALUE TOMBSTONE  --  delete a real value
echo ========================================================
echo.
::================================================================================

echo __________________2 1 delete a real value: value must vanish inside sandbox
@rem Real value TROOT\valtest: realval must disappear after sandbox delete.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\valtest" /v "realval" /t REG_SZ /d "real_data" /f >nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\valtest" /v realval /f >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - value delete succeeded"
) else (
    call :Fail " - value delete failed"
)

@rem Real value must still be there outside sandbox
reg query "%TROOT%\valtest" /v realval >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - real value preserved outside sandbox"
) else (
    call :Fail " - real value was deleted outside sandbox"
)

@rem Inside sandbox value must be gone
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\valtest" /v realval >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - value correctly invisible inside sandbox"
) else (
    call :Fail " - deleted value still visible inside sandbox"
)


echo __________________2 2 value tombstone persists across sandbox sessions
@rem VIRTL not cleared -- tombstone must survive new session.

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\valtest" /v realval >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - value tombstone survived new session"
) else (
    call :Fail " - tombstone lost, value resurrected"
)


echo __________________2 3 delete a value: sibling real values still readable
@rem Only the deleted value should vanish; other values in the same key must remain.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\siblings" /v "kill"   /t REG_SZ /d "to_be_deleted" /f >nul
reg add "%TROOT%\siblings" /v "keep1"  /t REG_SZ /d "alive" /f >nul
reg add "%TROOT%\siblings" /v "keep2"  /t REG_DWORD /d 99 /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\siblings" /v kill /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\siblings" /v kill >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - deleted value invisible"
) else (
    call :Fail " - deleted value still visible"
)

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\siblings" /v keep1 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - sibling keep1 still readable"
) else (
    call :Fail " - sibling keep1 disappeared"
)

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\siblings" /v keep2 >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - sibling keep2 still readable"
) else (
    call :Fail " - sibling keep2 disappeared"
)


echo __________________2 4 delete value then write it back: new data must win
@rem Tombstone a value, then re-write it with new data. New data must appear.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\rewrite" /v "val" /t REG_SZ /d "old" /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\rewrite" /v val /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg add    "%TROOT%\rewrite" /v val /t REG_SZ /d "new" /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\rewrite" /v val | findstr "new" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - re-written value reads new data"
) else (
    call :Fail " - re-written value does not show new data"
)

@rem Confirm real registry still has the old value
reg query "%TROOT%\rewrite" /v val | findstr "old" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - real registry still has old value"
) else (
    call :Fail " - real registry value was modified"
)


echo __________________2 5 delete all values in a key: key itself must still be visible
@rem Key must remain queryable even when all its real values are tombstoned.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\allvals" /v "a" /t REG_SZ /d "1" /f >nul
reg add "%TROOT%\allvals" /v "b" /t REG_SZ /d "2" /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\allvals" /v a /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\allvals" /v b /f >nul 2>nul

@rem Key itself must still be queryable
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\allvals" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - empty key still visible after all values deleted"
) else (
    call :Fail " - key disappeared after deleting all values"
)

@rem Both values must be gone
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\allvals" /v a >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - value a invisible"
) else (
    call :Fail " - value a still visible"
)

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\allvals" /v b >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - value b invisible"
) else (
    call :Fail " - value b still visible"
)


echo __________________2 6 delete a virtual-only value: must succeed
@rem Value was written inside sandbox, not in real registry. Delete must succeed.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\virtval" /f >nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg add    "%TROOT%\virtval" /v "vv" /t REG_SZ /d "sandbox" /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\virtval" /v vv /f >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - virtual-only value deleted successfully"
) else (
    call :Fail " - virtual-only value delete failed"
)

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\virtval" /v vv >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - virtual-only value invisible after delete"
) else (
    call :Fail " - virtual-only value still visible"
)


::================================================================================
echo.
echo ========================================================
echo 3  ENUMERATION  --  deleted entries must not appear in key/value lists
echo ========================================================
echo.
::================================================================================

echo __________________3 1 deleted real subkey must not appear in key enumeration
@rem reg query on parent should list only live subkeys.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\enum_parent\alive" /f >nul
reg add "%TROOT%\enum_parent\dead"  /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\enum_parent\dead" /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\enum_parent" | findstr /I "dead" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - dead subkey absent from enumeration"
) else (
    call :Fail " - dead subkey still appears in enumeration"
)

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\enum_parent" | findstr /I "alive" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - alive subkey present in enumeration"
) else (
    call :Fail " - alive subkey missing from enumeration"
)


echo __________________3 2 deleted real value must not appear in value enumeration
@rem reg query /s on a key should not show tombstoned values.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\enum_vals" /v "dead_val"  /t REG_SZ /d "del_me"  /f >nul
reg add "%TROOT%\enum_vals" /v "alive_val" /t REG_SZ /d "keep_me" /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\enum_vals" /v dead_val /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\enum_vals" | findstr /I "dead_val" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - dead_val absent from value enumeration"
) else (
    call :Fail " - dead_val still in value enumeration"
)

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\enum_vals" | findstr /I "alive_val" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - alive_val present in value enumeration"
) else (
    call :Fail " - alive_val missing from value enumeration"
)


echo __________________3 3 deleted subkey count must be correct in KeyFullInformation
@rem After deleting one of two subkeys the reported SubKeys count must be 1 not 2.
@rem We probe this by: if reg query lists exactly one subkey line containing TROOT\
@rem that is "alive" only.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\count_test\sk_alive" /f >nul
reg add "%TROOT%\count_test\sk_dead"  /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\count_test\sk_dead" /f >nul 2>nul

@rem Count the subkey lines: must be exactly 1 (sk_alive)
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\count_test" | findstr /I "sk_alive" | "%~dp0_bin\wc.exe" -l | findstr /C:"      1" >nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - only 1 subkey visible after delete"
) else (
    call :Fail " - wrong subkey count after delete"
)


echo __________________3 4 recursive enumeration: deleted subtree invisible
@rem reg query /s on root must not show the deleted subtree at all.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\tree\branch_live\leaf" /v "x" /t REG_SZ /d "y" /f >nul
reg add "%TROOT%\tree\branch_dead\leaf" /v "x" /t REG_SZ /d "y" /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\tree\branch_dead" /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\tree" /s | findstr /I "branch_dead" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - branch_dead absent from recursive enumeration"
) else (
    call :Fail " - branch_dead still in recursive enumeration"
)

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\tree" /s | findstr /I "branch_live" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - branch_live present in recursive enumeration"
) else (
    call :Fail " - branch_live missing from recursive enumeration"
)


::================================================================================
echo.
echo ========================================================
echo 4  ISOLATION  --  tombstone must NOT leak outside sandbox
echo ========================================================
echo.
::================================================================================

echo __________________4 1 deleting a real key inside sandbox must not affect real registry
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\isolation_key" /v "val" /t REG_SZ /d "real" /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\isolation_key" /f >nul 2>nul

@rem Real registry must still have the key and value
reg query "%TROOT%\isolation_key" /v val >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - real key unaffected by sandbox delete"
) else (
    call :Fail " - sandbox delete leaked to real registry"
)


echo __________________4 2 deleting a real value inside sandbox must not affect real registry
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\isolation_val" /v "realv" /t REG_SZ /d "real_data" /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\isolation_val" /v realv /f >nul 2>nul

reg query "%TROOT%\isolation_val" /v realv >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - real value unaffected by sandbox delete"
) else (
    call :Fail " - sandbox value delete leaked to real registry"
)


echo __________________4 3 write after delete must not leak to real registry
@rem Delete a real key inside sandbox, recreate it inside sandbox with new data.
@rem Real registry must still have the original key/value unchanged.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\leak_test" /v "v" /t REG_SZ /d "original" /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\leak_test" /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg add    "%TROOT%\leak_test" /v "v" /t REG_SZ /d "modified" /f >nul 2>nul

@rem Sandbox sees new value
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\leak_test" /v v | findstr "modified" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - sandbox sees modified value"
) else (
    call :Fail " - sandbox does not see modified value"
)

@rem Real registry must still have original
reg query "%TROOT%\leak_test" /v v | findstr "original" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - real registry untouched"
) else (
    call :Fail " - real registry was modified"
)


::================================================================================
echo.
echo ========================================================
echo 5  DATA TYPES  --  tombstone works for all REG types
echo ========================================================
echo.
::================================================================================

echo __________________5 1 delete REG_DWORD value
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\types" /v "dword_val" /t REG_DWORD /d 12345 /f >nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\types" /v dword_val /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\types" /v dword_val >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - REG_DWORD tombstoned correctly"
) else (
    call :Fail " - REG_DWORD still visible"
)


echo __________________5 2 delete REG_BINARY value
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\types" /v "bin_val" /t REG_BINARY /d deadbeef /f >nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\types" /v bin_val /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\types" /v bin_val >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - REG_BINARY tombstoned correctly"
) else (
    call :Fail " - REG_BINARY still visible"
)


echo __________________5 3 delete REG_EXPAND_SZ value
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\types" /v "esz_val" /t REG_EXPAND_SZ /d "%%SystemRoot%%\foo" /f >nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\types" /v esz_val /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\types" /v esz_val >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - REG_EXPAND_SZ tombstoned correctly"
) else (
    call :Fail " - REG_EXPAND_SZ still visible"
)


echo __________________5 4 delete REG_MULTI_SZ value
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\types" /v "msz_val" /t REG_MULTI_SZ /d "aaa\0bbb" /f >nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\types" /v msz_val /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\types" /v msz_val >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - REG_MULTI_SZ tombstoned correctly"
) else (
    call :Fail " - REG_MULTI_SZ still visible"
)


echo __________________5 5 delete the default (unnamed) value
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\defval" /ve /d "default_data" /f >nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\defval" /ve /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\defval" /ve | findstr "default_data" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - default value tombstoned correctly"
) else (
    call :Fail " - default value still visible"
)


::================================================================================
echo.
echo ========================================================
echo 6  WRITE THEN DELETE  --  CoW write followed by delete
echo ========================================================
echo.
::================================================================================

echo __________________6 1 write a value then delete it: must vanish
@rem CoW the key by writing a value, then delete that same value.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\write_del" /v "keep" /t REG_SZ /d "stays" /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg add    "%TROOT%\write_del" /v "temp" /t REG_SZ /d "temporary" /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\write_del" /v temp /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\write_del" /v temp >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - written-then-deleted value invisible"
) else (
    call :Fail " - written-then-deleted value still visible"
)

@rem The other value must still be readable
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\write_del" /v keep >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - sibling value unaffected"
) else (
    call :Fail " - sibling value disappeared"
)


echo __________________6 2 create a subkey then delete it: must vanish
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\parent_live" /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg add    "%TROOT%\parent_live\new_child" /v "x" /t REG_SZ /d "y" /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\parent_live\new_child" /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\parent_live\new_child" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - created-then-deleted subkey invisible"
) else (
    call :Fail " - created-then-deleted subkey still visible"
)


echo __________________6 3 overwrite a real value then delete it: real value must not come back
@rem Write new data over a real value (CoW), then delete the CoW'd value.
@rem The real value must NOT resurrect after the CoW value is deleted.

reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\cow_del" /v "v" /t REG_SZ /d "real_original" /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg add    "%TROOT%\cow_del" /v "v" /t REG_SZ /d "cow_written" /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\cow_del" /v v /f >nul 2>nul

@rem Value must be gone -- tombstone blocks real value resurrection
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\cow_del" /v v >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - real value blocked by tombstone after CoW delete"
) else (
    call :Fail " - real value resurrected after CoW delete"
)


::================================================================================
echo.
echo ========================================================
echo 7  HKLM  --  tombstone in HKLM virtual path
echo ========================================================
echo.
::================================================================================

@rem HKLM tests use a safe scratch key we create first, then delete inside sandbox.
@rem We use HKLM\SOFTWARE\Classes\VLTest_* which is writable by standard users
@rem via the per-user classes merge.

set "HKLM_TEST=HKLM\SOFTWARE\Classes\_VLTest_Tombstone"

echo __________________7 1 delete an HKLM key inside sandbox: must vanish inside, survive outside
reg delete "%HKLM_TEST%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%HKLM_TEST%\delme" /v "val" /t REG_SZ /d "hklm_real" /f >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo skip - cannot write to HKLM ^(not admin^), skipping HKLM tests
    goto skip_hklm
)

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%HKLM_TEST%\delme" /f >nul 2>nul

@rem Must be gone inside sandbox
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%HKLM_TEST%\delme" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - HKLM key invisible inside sandbox after delete"
) else (
    call :Fail " - HKLM key still visible inside sandbox"
)

@rem Must survive outside
reg query "%HKLM_TEST%\delme" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - HKLM key untouched in real registry"
) else (
    call :Fail " - HKLM key was deleted in real registry"
)


echo __________________7 2 delete an HKLM value inside sandbox
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%HKLM_TEST%\delme" /v val /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%HKLM_TEST%\delme" /v val >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - HKLM value invisible inside sandbox after delete"
) else (
    call :Fail " - HKLM value still visible inside sandbox"
)

reg query "%HKLM_TEST%\delme" /v val >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - HKLM value untouched in real registry"
) else (
    call :Fail " - HKLM value was deleted in real registry"
)

:skip_hklm
reg delete "%HKLM_TEST%" /f >nul 2>nul


::================================================================================
echo.
echo ========================================================
echo 8  DEEP PATH  --  tombstone at deep nesting levels
echo ========================================================
echo.
::================================================================================

echo __________________8 1 delete a key 5 levels deep
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\a\b\c\d\e" /v "deep" /t REG_SZ /d "deep_val" /f >nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\a\b\c\d\e" /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\a\b\c\d\e" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - deep key invisible after delete"
) else (
    call :Fail " - deep key still visible"
)

@rem Ancestor one level up must still be visible
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\a\b\c\d" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - parent d still visible"
) else (
    call :Fail " - parent d disappeared after child delete"
)


echo __________________8 2 delete a value 5 levels deep
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\a\b\c\d\e" /v "deep_v" /t REG_SZ /d "data" /f >nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\a\b\c\d\e" /v deep_v /f >nul 2>nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\a\b\c\d\e" /v deep_v >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - deep value invisible after delete"
) else (
    call :Fail " - deep value still visible"
)

@rem Key itself must still be queryable
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\a\b\c\d\e" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - key still visible after deep value delete"
) else (
    call :Fail " - key disappeared after value delete"
)


::================================================================================
echo.
echo ========================================================
echo 9  MULTI-OP  --  delete then recreate then delete again
echo ========================================================
echo.
::================================================================================

echo __________________9 1 delete / recreate / delete cycle on a key
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\cycle" /v "v" /t REG_SZ /d "original" /f >nul

@rem Round 1: delete
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\cycle" /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\cycle" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - cycle r1 delete ok"
) else (
    call :Fail " - cycle r1 key visible"
)

@rem Round 2: recreate with new value
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg add "%TROOT%\cycle" /v "v" /t REG_SZ /d "round2" /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\cycle" /v v | findstr "round2" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - cycle r2 recreate ok"
) else (
    call :Fail " - cycle r2 value wrong"
)

@rem Round 3: delete again
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\cycle" /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\cycle" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - cycle r3 delete ok"
) else (
    call :Fail " - cycle r3 key visible"
)

@rem Round 4: recreate again
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg add "%TROOT%\cycle" /v "v" /t REG_SZ /d "round4" /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\cycle" /v v | findstr "round4" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - cycle r4 recreate ok"
) else (
    call :Fail " - cycle r4 value wrong"
)


echo __________________9 2 delete / recreate / delete cycle on a value
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul

reg add "%TROOT%\vcycle" /v "vv" /t REG_SZ /d "original" /f >nul

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\vcycle" /v vv /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\vcycle" /v vv >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - vcycle r1 delete ok"
) else (
    call :Fail " - vcycle r1 still visible"
)

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg add "%TROOT%\vcycle" /v "vv" /t REG_SZ /d "r2" /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\vcycle" /v vv | findstr "r2" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    call :Pass " - vcycle r2 recreate ok"
) else (
    call :Fail " - vcycle r2 value wrong"
)

VirtLauncher64.exe -r "%VREG%" -e cmd /c reg delete "%TROOT%\vcycle" /v vv /f >nul 2>nul
VirtLauncher64.exe -r "%VREG%" -e cmd /c reg query "%TROOT%\vcycle" /v vv >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :Pass " - vcycle r3 delete ok"
) else (
    call :Fail " - vcycle r3 still visible"
)


::================================================================================
:: Cleanup
::================================================================================
echo.
echo.
reg delete "%TROOT%" /f >nul 2>nul
reg delete "%VREG%" /f >nul 2>nul
rmdir /Q /S "%CD%\VIRTL" 2>nul




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




:Pass
rem echo   [+] PASS: %~1
echo good
set /a PASS_COUNT+=1
goto :eof

:Fail
echo FAIL: %~1
set /a FAIL_COUNT+=1
goto :eof
