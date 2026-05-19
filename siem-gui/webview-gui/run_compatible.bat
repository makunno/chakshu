@echo off
REM Cyber Chakshu SIEM Desktop Launcher with Graphics Compatibility

echo Starting Cyber Chakshu SIEM Desktop with graphics compatibility fixes...

REM Set environment variables for better Qt WebEngine compatibility
set QTWEBENGINE_CHROMIUM_FLAGS=--disable-gpu --disable-software-rasterizer --disable-web-security --allow-running-insecure-content --no-sandbox
set QT_QPA_PLATFORM=windows:dpiawareness=0
set QT_OPENGL=software
set QTWEBENGINE_DISABLE_GPU=1

REM Run the application
python main.py

pause