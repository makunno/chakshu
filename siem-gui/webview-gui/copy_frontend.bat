@echo off
REM Copy React frontend build to static folder for Full EXE

echo Checking for React build...

set SOURCE=..\..\siem-tool\frontend\dist
set DESTINATION=static

if not exist "%SOURCE%" (
    echo Source folder not found: %SOURCE%
    echo Using online frontend by default...
    goto end
)

echo Copying frontend files from %SOURCE% to %DESTINATION%...

REM Copy index.html
if exist "%SOURCE%\index.html" (
    copy /Y "%SOURCE%\index.html" "%DESTINATION%\index.html"
    echo Copied index.html
)

REM Copy and merge assets folder
if exist "%SOURCE%\assets" (
    if not exist "%DESTINATION%\assets" mkdir "%DESTINATION%\assets"
    xcopy /Y /E /I "%SOURCE%\assets" "%DESTINATION%\assets" >nul
    echo Copied assets folder
)

REM Copy images folder
if exist "%SOURCE%\images" (
    if not exist "%DESTINATION%\images" mkdir "%DESTINATION%\images"
    xcopy /Y /E /I "%SOURCE%\images" "%DESTINATION%\images" >nul
    echo Copied images folder
)

echo.
echo Frontend files copied successfully!
echo The Full EXE will now bundle the local frontend.

:end
pause
