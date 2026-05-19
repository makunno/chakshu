@echo off
REM Build Cyber Chakshu Full EXE (Browser + Flask Backend)
echo Building Cyber Chakshu-Full.exe...

pyinstaller --clean --noconfirm ^
    --name "Cyber Chakshu-Full" ^
    --windowed ^
    --onefile ^
    --collect-all flask ^
    --collect-all werkzeug ^
    --collect-all sklearn ^
    --collect-all numpy ^
    --hidden-import PySide6.QtWebEngineWidgets ^
    --hidden-import PySide6.QtWebEngineCore ^
    main.py

echo.
if exist "dist\Cyber Chakshu-Full.exe" (
    echo Build complete! EXE: dist/Cyber Chakshu-Full.exe
    echo Size: ~312 MB (embedded webview + Flask backend)
) else (
    echo Build may have failed. Check dist folder.
)
echo.
pause
