#!/bin/bash
# Cyber Chakshu SIEM Desktop Launcher with Graphics Compatibility (Cross-platform)

echo "Cyber Chakshu SIEM Desktop with graphics compatibility fixes..."
echo "Platform: $(uname -s)"

# Set environment variables for better Qt WebEngine compatibility
export QTWEBENGINE_CHROMIUM_FLAGS="--disable-gpu --disable-software-rasterizer --disable-web-security --allow-running-insecure-content --no-sandbox"
export QTWEBENGINE_DISABLE_GPU=1

# Platform-specific settings
case "$(uname -s)" in
    Linux*)
        export QT_QPA_PLATFORM=xcb
        export QT_OPENGL=software
        echo "Linux detected - using software OpenGL"
        ;;
    Darwin*)
        echo "macOS detected - using default settings"
        ;;
    *)
        echo "Unknown platform - using default settings"
        ;;
esac

# Run the application
python3 main.py