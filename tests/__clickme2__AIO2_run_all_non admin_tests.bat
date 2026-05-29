@echo off
SETLOCAL EnableDelayedExpansion
CD /D "%~dp0"

mode con | findstr "32766" >nul|| mode con lines=32766 COLS=120 &REM prevent "mode con" from clearing the console

set "DoNotPause=yes"

echo ========================================
echo Starting Test Batch Runner
echo ========================================
echo.

set "passCount=0"
set "failCount=0"

:: Find files matching _test*.bat, exclude those containing USE_ADMIN
:: The 2>nul prevents an error message if no files are found initially
for /f "delims=" %%F in ('dir /b /a-d "_test*.bat" 2^>nul ^| findstr /v /i "USE_ADMIN"') do (
    echo Running: "%%F"
    
    :: Use call to run the script so control returns to this runner
    call %%F
    
    :: Immediately capture the exit code
    set "exitCode=!errorlevel!"
    
    :: Evaluate the exit code and store the results in pseudo-arrays
    if !exitCode! equ 0 (
        echo  -^> [PASS]
        set "passArray[!passCount!]=%%F"
        set /a passCount+=1
    ) else (
        echo  -^> [FAIL] ^(Exit Code: !exitCode!^)
        set "failArray[!failCount!]=%%F"
        set /a failCount+=1
    )
    echo.
)

echo ========================================
echo Test Summary
echo ========================================
echo Total Passed : !passCount!
echo Total Failed : !failCount!
echo.

if !passCount! gtr 0 (
    echo --- Passing Tests ---
    set /a pLimit=!passCount!-1
    for /L %%i in (0, 1, !pLimit!) do (
        echo   [+] !passArray[%%i]!
    )
)

if !failCount! gtr 0 (
    echo.
    echo --- Failing Tests ---
    set /a fLimit=!failCount!-1
    for /L %%i in (0, 1, !fLimit!) do (
        echo   [-] !failArray[%%i]!
    )
)

echo ========================================

echo.
if %failCount% equ 0 (
    echo  [OK] ALL TESTS PASSED SUCCESSFULLY!
    color 2F
) else (
    echo  [X] SOME TESTS FAILED!
    color 4F
)
echo.

endlocal

if not "%DoNotPause%"=="yes" pause
exit /b %failCount%