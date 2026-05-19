#!/bin/bash
# Cyber Chakshu SIEM Desktop - Cross-platform Graphics Diagnostics

echo "Cyber Chakshu SIEM Desktop - Graphics Compatibility Check"
echo "==================================================="
echo "Platform: $(uname -s)"
echo

# Check system information
echo "System Information:"
echo "CPU: $(uname -m)"
echo "Kernel: $(uname -r)"
echo

# Check available memory
echo "Memory Information:"
if command -v free &> /dev/null; then
    free -h
elif command -v vm_stat &> /dev/null; then
    vm_stat
else
    echo "Memory info not available"
fi
echo

# Check GPU info (platform-specific)
echo "Graphics Information:"
case "$(uname -s)" in
    Linux*)
        if command -v lspci &> /dev/null; then
            lspci | grep -i vga
        elif command -v glxinfo &> /dev/null; then
            glxinfo | grep -E "(OpenGL vendor|OpenGL renderer|OpenGL version)"
        else
            echo "GPU info not available (install pciutils or mesa-utils)"
        fi
        ;;
    Darwin*)
        system_profiler SPDisplaysDataType | grep -E "(Chipset Model|VRAM)"
        ;;
    *)
        echo "GPU detection not supported on this platform"
        ;;
esac
echo

# Check Python and Qt versions
echo "Software Versions:"
python3 --version
python3 -c "import PySide6; print('PySide6 version:', PySide6.__version__)" 2>/dev/null || echo "PySide6 not found"
echo

echo "Attempting to run with graphics compatibility fixes..."
echo "If you see graphics errors, try the browser fallback mode."
echo
echo "Press Enter to continue..."
read -r

# Run with compatibility fixes
./run_compatible.sh