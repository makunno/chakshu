@echo off
chcp 65001 >nul
echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║          Cyber Chakshu SIEM - Installation Wizard                 ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found!
    echo.
    echo Please install Python 3.9 or higher from:
    echo https://python.org/downloads
    echo.
    echo After installing Python, run this installer again.
    echo.
    pause
    exit /b 1
)

for /f "tokens=2 delims=." %%a in ('python -c "import sys; print(sys.version_info.minor)"') do set PYTHON_MINOR=%%a
if %PYTHON_MINOR% lss 9 (
    echo [!] Python 3.9+ required. Found Python 3.%PYTHON_MINOR%
    echo Please update Python from https://python.org/downloads
    pause
    exit /b 1
)

echo [v] Python found

REM Get current directory
set "INSTALL_DIR=%~dp0"
echo Installing to: %INSTALL_DIR%

echo.
echo [1/4] Installing Python dependencies...
echo ----------------------------------------
pip install -q flask flask-cors requests
pip install -q PySide6 scikit-learn numpy
echo [v] Dependencies installed

echo.
echo [2/4] Creating shortcuts...
echo ----------------------------------------

REM Create Start Menu shortcuts
set "START_MENU=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Cyber Chakshu SIEM"
if not exist "%START_MENU%" mkdir "%START_MENU%"

REM Create Cyber Chakshu.lnk (connects to online)
echo Set oWS = WScript.CreateObject("WScript.Shell") > create_shortcut.vbs
echo Set oLink = oWS.CreateShortcut("%START_MENU%\Cyber Chakshu SIEM.lnk") >> create_shortcut.vbs
echo oLink.TargetPath = "%INSTALL_DIR%Cyber Chakshu-Browser.exe" >> create_shortcut.vbs
echo oLink.WorkingDirectory = "%INSTALL_DIR%" >> create_shortcut.vbs
echo oLink.Description = "Cyber Chakshu SIEM - Online" >> create_shortcut.vbs
echo oLink.IconLocation = "shell32.dll,21" >> create_shortcut.vbs
echo oLink.Save >> create_shortcut.vbs
cscript //nologo create_shortcut.vbs
del create_shortcut.vbs

REM Create Cyber Chakshu Local.lnk
echo Set oWS = WScript.CreateObject("WScript.Shell") > create_shortcut.vbs
echo Set oLink = oWS.CreateShortcut("%START_MENU%\Cyber Chakshu SIEM (Local).lnk") >> create_shortcut.vbs
echo oLink.TargetPath = "%INSTALL_DIR%Cyber Chakshu-Full.exe" >> create_shortcut.vbs
echo oLink.WorkingDirectory = "%INSTALL_DIR%" >> create_shortcut.vbs
echo oLink.Description = "Cyber Chakshu SIEM - Local Backend" >> create_shortcut.vbs
echo oLink.IconLocation = "shell32.dll,21" >> create_shortcut.vbs
echo oLink.Save >> create_shortcut.vbs
cscript //nologo create_shortcut.vbs
del create_shortcut.vbs

REM Create desktop shortcut
set "DESKTOP=%USERPROFILE%\Desktop"
echo Set oWS = WScript.CreateObject("WScript.Shell") > create_shortcut.vbs
echo Set oLink = oWS.CreateShortcut("%DESKTOP%\Cyber Chakshu SIEM.lnk") >> create_shortcut.vbs
echo oLink.TargetPath = "%INSTALL_DIR%Cyber Chakshu-Browser.exe" >> create_shortcut.vbs
echo oLink.WorkingDirectory = "%INSTALL_DIR%" >> create_shortcut.vbs
echo oLink.Description = "Cyber Chakshu SIEM" >> create_shortcut.vbs
echo oLink.IconLocation = "shell32.dll,21" >> create_shortcut.vbs
echo oLink.Save >> create_shortcut.vbs
cscript //nologo create_shortcut.vbs
del create_shortcut.vbs

echo [v] Shortcuts created

echo.
echo [3/4] Creating batch files...
echo ----------------------------------------

REM Create run_backend.bat
echo @echo off > "%INSTALL_DIR%run_backend.bat"
echo echo Starting Cyber Chakshu SIEM Backend... >> "%INSTALL_DIR%run_backend.bat"
echo cd /d "%%~dp0" >> "%INSTALL_DIR%run_backend.bat"
echo python -m flask run --host=127.0.0.1 --port=5000 >> "%INSTALL_DIR%run_backend.bat"
echo if errorlevel 1 ^( >> "%INSTALL_DIR%run_backend.bat"
echo     echo Error starting backend. Make sure dependencies are installed. >> "%INSTALL_DIR%run_backend.bat"
echo     pause >> "%INSTALL_DIR%run_backend.bat"
echo ^) >> "%INSTALL_DIR%run_backend.bat"

REM Create run_app.bat
echo @echo off > "%INSTALL_DIR%run_app.bat"
echo echo Starting Cyber Chakshu SIEM... >> "%INSTALL_DIR%run_app.bat"
echo cd /d "%%~dp0" >> "%INSTALL_DIR%run_app.bat"
echo start "" Cyber Chakshu-Full.exe >> "%INSTALL_DIR%run_app.bat"

echo [v] Batch files created

echo.
echo [4/4] Verifying installation...
echo ----------------------------------------
python -c "import flask; import PySide6; import sklearn" 2>nul
if errorlevel 1 (
    echo [!] Some dependencies may not have installed correctly
    echo Try running: pip install flask PySide6 scikit-learn numpy
) else (
    echo [v] All dependencies verified
)

echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║                    Installation Complete!                       ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.
echo OPTIONS:
echo.
echo [1] Run Cyber Chakshu SIEM (Online)     - Uses online backend
echo [2] Run Cyber Chakshu SIEM (Local)       - Requires running backend
echo [3] Start Local Backend Only          - Starts Flask server
echo [4] Exit
echo.
set /p choice="Enter choice [1-4]: "
if "%choice%"=="1" (
    start "" "%INSTALL_DIR%Cyber Chakshu-Browser.exe"
)
if "%choice%"=="2" (
    echo.
    echo Starting local backend first...
    start /B "" cmd /c "python -m flask run --host=127.0.0.1 --port=5000"
    timeout /t 3 /nobreak >nul
    start "" "%INSTALL_DIR%Cyber Chakshu-Full.exe"
)
if "%choice%"=="3" (
    start cmd /k "python -m flask run --host=127.0.0.1 --port=5000"
)
if "%choice%"=="4" (
    echo Goodbye!
)

echo.
echo Shortcuts have been created on your Desktop and Start Menu.
echo.
