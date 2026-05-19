@echo off
REM Build Cyber Chakshu Browser EXE (Embedded WebView)
echo Building Cyber Chakshu-Browser.exe...

pyinstaller --clean --noconfirm ^
    --name "Cyber Chakshu-Browser" ^
    --windowed ^
    --onefile ^
    main_browser.py

echo.
if exist "dist\Cyber Chakshu-Browser.exe" (
    echo Build complete! EXE: dist/Cyber Chakshu-Browser.exe
    echo Size: ~201 MB (embedded Qt WebEngine)
) else (
    echo Build may have failed. Check dist folder.
)
echo.
pause
