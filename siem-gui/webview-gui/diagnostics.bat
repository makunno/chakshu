@echo off
REM Cyber Chakshu SIEM Desktop - Graphics Diagnostics

echo Cyber Chakshu SIEM Desktop - Graphics Compatibility Check
echo ====================================================
echo.
echo Checking graphics compatibility...
echo.

REM Check GPU info
echo GPU Information:
wmic path win32_VideoController get name,driverversion
echo.

REM Check DirectX version
echo DirectX Version:
dxdiag /t dxdiag_output.txt >nul 2>&1
if exist dxdiag_output.txt (
    findstr /C:"DirectX Version" dxdiag_output.txt
    del dxdiag_output.txt >nul 2>&1
) else (
    echo Could not determine DirectX version
)
echo.

REM Check available memory
echo System Memory:
wmic ComputerSystem get TotalPhysicalMemory
echo.

echo.
echo Attempting to run with graphics compatibility fixes...
echo If you see graphics errors, try the browser fallback mode.
echo.
echo Press any key to continue...
pause >nul

REM Run with compatibility fixes
python main.py