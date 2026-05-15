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


echo.
echo ========================================================
echo move
echo ========================================================
echo.

echo __________________1 1 move and overwrite a real file 
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


if exist "%CD%\VIRTL\%testdir::=%\c" (
    color 4F & echo bad
) else (
    echo good
)

if exist "%CD%\VIRTL\%testdir::=%\v" (
    echo good
) else (
    color 4F & echo bad
)



echo __________________1 2 1 move and overwrite a real file
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


echo __________________1 2 2 move and overwrite a real file
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


echo __________________1 3 move and overwrite a real folder
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

@rem cc folder should not exist now thanks to the tombstone
if exist "%CD%\VIRTL\%testdir::=%\cc" (
    color 4F & echo bad
) else (
    echo good
)

if exist "%CD%\VIRTL\%testdir::=%\vv\cc" (
    echo good
) else (
    color 4F & echo bad
)


echo.
echo ========================================================
echo rename
echo ========================================================
echo.

echo __________________2 1 rename a real folder to an non existent folder
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


if exist "%CD%\VIRTL\%testdir::=%\cc" (
    color 4F & echo bad
) else (
    echo good
)

if exist "%CD%\VIRTL\%testdir::=%\vvc" (
    echo good
) else (
    color 4F & echo bad
)


echo __________________2 2 rename a real folder to an existent folder
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%\cc"
mkdir "%testdir%\vvc"
@rem TODO uncomment this and delete the one below it when the buf is fixeds
@rem VirtLauncher64.exe -r -f -e cmd /c rename "%testdir%\cc" vvc 2>&1 | findstr /C:"A duplicate file name exists" | "%~dp0_bin\wc.exe" -l | findstr /C:"      1"
VirtLauncher64.exe -r -f -e cmd /c rename "%testdir%\cc" vvc 2>&1 | findstr /C:"A duplicate file name exists"
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)


echo __________________2 3 rename a real file to an non existent file
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


if exist "%CD%\VIRTL\%testdir::=%\fileee" (
    color 4F & echo bad
) else (
    echo good
)

if exist "%CD%\VIRTL\%testdir::=%\fileeerenamed" (
    echo good
) else (
    color 4F & echo bad
)


echo __________________2 4 rename a real file to an existent file
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%"
echo sdfsdf>"%testdir%\fileee"
echo sdfsdf>"%testdir%\fileee2"
@rem it should print one line "A duplicate file name exists" ,not multiple times but just once hence the wc use
@rem TODO uncomment this and delete the one below it when the buf is fixeds
@rem VirtLauncher64.exe -r -f -e cmd /c rename "%testdir%\fileee" fileee2 2>&1 | findstr /C:"A duplicate file name exists" | "%~dp0_bin\wc.exe" -l | findstr /C:"      1"
VirtLauncher64.exe -r -f -e cmd /c rename "%testdir%\fileee" fileee2 2>&1 | findstr /C:"A duplicate file name exists"
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)


echo.
echo ========================================================
echo copy
echo ========================================================
echo.

echo __________________3 1 copy a real folder to an non existent folder
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%\cc"
echo dsfsd>"%testdir%\cc\ggg"

@rem cmd /C xcopy "%testdir%\cc" "%testdir%\vvc" /I /E /Q /H /R
@rem pause

@rem it gave error: Invalid path
VirtLauncher64.exe -r -f -e cmd /c xcopy "%testdir%\cc" "%testdir%\vvc" /I /E /Q /H /R
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)


if exist "%CD%\VIRTL\%testdir::=%\vvc\ggg" (
    echo good
) else (
    color 4F & echo bad
)


echo __________________3 2 copy a real folder to an existent folder
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%\cc"
mkdir "%testdir%\vvc"
echo dsfsd>"%testdir%\cc\ggg"
echo dsfsd>"%testdir%\vvc\ggg"

VirtLauncher64.exe -r -f -e cmd /S /c "echo y|xcopy "%testdir%\cc" "%testdir%\vvc" /I /E /Q /H /R"
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)


if exist "%CD%\VIRTL\%testdir::=%\vvc\ggg" (
    echo good
) else (
    color 4F & echo bad
)

echo __________________3 3 copy a real file to an non existent file
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%"
echo sdfsdf>"%testdir%\fileee"

@rem cmd /c copy "%testdir%\fileee" "%testdir%\fileeecopy"
@rem pause

@rem the file is copied but it print this error: The file cannot be copied onto itself.
VirtLauncher64.exe -r -f -e cmd /c copy "%testdir%\fileee" "%testdir%\fileeecopy"
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)


if exist "%CD%\VIRTL\%testdir::=%\fileeecopy" (
    echo good
) else (
    color 4F & echo bad
)


echo __________________3 4 copy a real file to an existent file
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%"
echo sdfsdf>"%testdir%\fileee"
echo sdfsdf>"%testdir%\fileee2"

@rem the file is copied but it print this error: The file cannot be copied onto itself.
VirtLauncher64.exe -r -f -e cmd /c copy "%testdir%\fileee" "%testdir%\fileee2" 
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)


if exist "%CD%\VIRTL\%testdir::=%\fileee2" (
    echo good
) else (
    color 4F & echo bad
)



echo.
echo ========================================================
echo delete
echo ========================================================
echo.

echo __________________4 1 delete a folder
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%"
echo sdfsdf>"%testdir%\fileee"

@rem cmd /S /c "echo y|rmdir /S "%testdir%" "
@rem pause

@rem it gave this: The directory is not empty.  it should not because the same command without virtuaisation does not do like that!
VirtLauncher64.exe -r -f -e cmd /S /c "echo y|rmdir /S "%testdir%" "
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)


if exist "%CD%\VIRTL\%testdir::=%\fileee" (
    color 4F & echo bad
) else (
    echo good
)



echo __________________4 2 delete a file
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%"
echo sdfsdf>"%testdir%\fileee"

@rem cmd /c del "%testdir%\fileee"
@rem pause

@rem this gave error: Incorrect function.
VirtLauncher64.exe -r -f -e cmd /c del "%testdir%\fileee"
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)


if exist "%CD%\VIRTL\%testdir::=%\fileee" (
    color 4F & echo bad
) else (
    echo good
)



echo.
echo ========================================================
echo read/write
echo ========================================================
echo.

echo __________________5 1 read
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%"
echo outside>"%testdir%\fileee"

VirtLauncher64.exe -r -f -e cmd /c type "%testdir%\fileee" | findstr outside >nul
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)



echo __________________5 2 write
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%" 2>nul

mkdir "%testdir%"
echo outside>"%testdir%\fileee"

VirtLauncher64.exe -r -f -e cmd /S /c "echo inside>"%testdir%\fileee" "
VirtLauncher64.exe -r -f -e cmd /c type "%testdir%\fileee" | findstr inside >nul
if %ERRORLEVEL% EQU 0 (
    echo good
) else (
    color 4F & echo bad
)




:: ================================================================================================================
echo.
echo.
rmdir /Q /S "%CD%\VIRTL" 2>nul
rmdir /Q /S "%testdir%"
pause


