@echo off
REM Cyber Chakshu Build Script - Builds both EXE versions

echo ============================================
echo Cyber Chakshu SIEM Build Script
echo ============================================
echo.

REM Install PyInstaller if not installed
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
    echo.
)

echo Choose build option:
echo [1] Cyber Chakshu-Browser.exe  - Embedded webview (~201 MB)
echo [2] Cyber Chakshu-Full.exe     - Webview + Flask backend (~312 MB)
echo [3] Build Both
echo.

set /p choice="Enter choice [1-3]: "
if "%choice%"=="1" goto browser
if "%choice%"=="2" goto full
if "%choice%"=="3" goto both
echo Invalid choice
goto end

:browser
echo.
echo Building Cyber Chakshu-Browser.exe...
pyinstaller --clean --noconfirm ^
    --name "Cyber Chakshu-Browser" ^
    --windowed ^
    --onefile ^
    --icon "icon.ico" ^
    main_browser.py
echo.
echo ============================================
echo Build complete!
echo EXE: dist\Cyber Chakshu-Browser.exe
echo ============================================
goto end

:full
echo.
echo Building Cyber Chakshu-Full.exe...
pyinstaller --clean --noconfirm ^
    --name "Cyber Chakshu-Full" ^
    --windowed ^
    --onefile ^
    --hidden-import PySide6.QtWebEngineWidgets ^
    --hidden-import PySide6.QtWebEngineCore ^
    --hidden-import flask ^
    --hidden-import werkzeug ^
    --icon "icon.ico" ^
    main.py
echo.
echo ============================================
echo Build complete!
echo EXE: dist\Cyber Chakshu-Full.exe
echo ============================================
goto end

:both
echo.
echo Building Cyber Chakshu-Browser.exe...
pyinstaller --clean --noconfirm ^
    --name "Cyber Chakshu-Browser" ^
    --windowed ^
    --onefile ^
    --icon "icon.ico" ^
    main_browser.py

echo.
echo Building Cyber Chakshu-Full.exe...
pyinstaller --clean --noconfirm ^
    --name "Cyber Chakshu-Full" ^
    --windowed ^
    --onefile ^
    --hidden-import PySide6.QtWebEngineWidgets ^
    --hidden-import PySide6.QtWebEngineCore ^
    --hidden-import flask ^
    --hidden-import werkzeug ^
    --icon "icon.ico" ^
    main.py

echo.
echo ============================================
echo All builds complete!
echo EXEs in dist\ folder:
echo   - Cyber Chakshu-Browser.exe (~201 MB)
echo   - Cyber Chakshu-Full.exe (~312 MB)
echo ============================================
goto end

:end
echo.
pause
