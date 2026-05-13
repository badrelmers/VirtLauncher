@echo off
SETLOCAL
CD /D "%~dp0"

::_______________________________________________
REM set VLAUNCHER_VERBOSE=true
 set VLAUNCHER_DEBUG=true


::_______________________________________________
color 2F
:: --- Configuration ---
set "BUILD_DIR=..\build"
cd "%BUILD_DIR%"

set "testdir=c:\test11_merged_write"
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul




echo __________________1
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%" 2>nul
echo ccc>"%testdir%\c"
echo vvv>"%testdir%\v"

@rem i use /-Y to force prompting to confirm i want overwrite an existing destination file, this is necesar because move do not prompt when i use it inside cmd /C !! 
@rem echo y| will answer automatically to the prompt
@rem if findstr find Overwrite then our tool work correctly like sandboxie: merging write; in the past i just moved without prompting because i used a diferent logic where the virtualizer merge the view but does not merge the writes
@rem in sandboxie if a real folder have a file called "aaa.txt"  and the virtual folder do not have it, and i attempt to copy and paste that file using a sandboxed explorer i get  a second file called "aaa  - Copy.txt" created inside the virtual folder, so it considers a real file as a file existent in the virtual folder when in fact it exist only in the real folder

VirtLauncher64.exe -r -f -e cmd /S /C "echo y|move /-Y "%testdir%\c" "%testdir%\v" " | findstr Overwrite >nul
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)



echo __________________2 1
@rem this bug was fixed by the commit where i added STATUS_NO_SUCH_FILE not with the merge write commit
@rem the bug happen if the dir where we move the files exist in the virtual dir

rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%" 2>nul
echo ccc>"%testdir%\c"
echo vvv>"%testdir%\v"
mkdir "%CD%\VIRTL\%testdir::=%"
VirtLauncher64.exe -r -f -e cmd /c move "%testdir%\c" "%testdir%\v" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)


echo __________________2 2
@rem the bug does not happen if the dir where we move the files does not exist in the virtual dir

rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%" 2>nul
echo ccc>"%testdir%\c"
echo vvv>"%testdir%\v"
rmdir "%CD%\VIRTL\%testdir::=%" 2>nul
VirtLauncher64.exe -r -f -e cmd /c move "%testdir%\c" "%testdir%\v" >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)


echo __________________3 1
@rem test folder overwrite
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%\cc"
mkdir "%testdir%\vv\cc"
VirtLauncher64.exe -r -f -e cmd /S /C "echo y|move /-Y "%testdir%\cc" "%testdir%\vv" " | findstr Overwrite >nul
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)

echo __________________3 2
@rem cc folder should not exist now thanks to the tombstone
VirtLauncher64.exe -r -f -e cmd /S /C "dir /b "%testdir%" " | findstr cc >nul
if %ERRORLEVEL% EQU 0 (
    color 4F & echo bad
) else (
    echo good
)


echo __________________4
@rem The system cannot find the file specified

rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%\cc"
VirtLauncher64.exe -r -f -e cmd /c rename "%testdir%\cc" vvc
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)

echo __________________5
@rem The system cannot find the file specified

rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%"
echo sdfsdf>"%testdir%\fileee"
VirtLauncher64.exe -r -f -e cmd /c rename "%testdir%\fileee" fileeerenamed
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)






@rem _______________________________________________________

rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%"
pause


