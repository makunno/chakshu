# Cyber Chakshu SIEM Desktop Application

**Modern desktop SIEM tool with PySide6 GUI, embedded WebView, and intelligent backend switching between local and online APIs.**

## 🚀 Features

### 🎨 **PySide6 Native GUI**
- **Modern dark theme** matching professional applications
- **Backend selection panel** with real-time status monitoring
- **Embedded WebView** containing the full React frontend
- **Responsive controls** and intuitive user interface

### 🌐 **Intelligent Backend Management**
- **Automatic detection** of localhost and online backends
- **Real-time switching** between backends without restart
- **Local backend control** - start/stop Flask server from GUI
- **Online fallback** to `https://freekhana-frontend.pages.dev`
- **Status indicators** - real-time availability display with ✓/✗ symbols

### 🔧 **Complete SIEM Engine**
- **56+ log parsers** for all major system types
- **ML-powered anomaly detection** with Isolation Forest
- **Attack chain correlation** across multiple sources
- **MITRE ATT&CK framework** mapping and recommendations

### 🧵 **Robust Thread Management**
- **Clean thread lifecycle** with proper startup/shutdown
- **Resource cleanup** prevents memory leaks
- **Qt signal handling** for thread-safe operations
- **Graceful error recovery** during backend failures

## 🚀 Quick Start

### Cross-Platform Setup

#### Linux/macOS Setup
```bash
cd webview-gui
pip install -r requirements.txt

# For graphics compatibility issues, use:
./run_compatible.sh

# Or run diagnostics first:
./diagnostics.sh

# Browser fallback (most compatible):
python main_browser.py
```

#### Windows Setup
```bash
cd webview-gui
pip install -r requirements.txt

# For graphics compatibility issues, use:
run_compatible.bat

# Or run diagnostics first:
diagnostics.bat

# Browser fallback (most compatible):
python main_browser.py
```

#### Manual Setup (All Platforms)
```bash
cd webview-gui
pip install -r requirements.txt
python main.py  # Main embedded WebView version
python main_browser.py  # Browser fallback version
```

## 🌐 Backend Options

The application automatically detects and switches between backends:

### Automatic Detection
- **Primary**: Local backend at `http://127.0.0.1:5000` (if available)
- **Fallback**: Online backend at `https://freekhana-frontend.pages.dev`

### Manual Control
```bash
# Force online backend (skip local detection)
python run.py --online

# Force local backend (start even if not available)
python run.py  # Will prompt for choice if localhost unavailable

# GUI Controls for Local Backend
# - "Start Local Backend" button: Starts the Flask server
# - "Stop Local Backend" button: Stops the running Flask server (appears when server is running)
```

### Backend Features Comparison

| Feature | Local Backend | Online Backend |
|---------|---------------|----------------|
| **Speed** | ⚡ Fast (local) | 🌐 Depends on connection |
| **Privacy** | 🔒 Private | 📤 Data sent to server |
| **Availability** | 🏠 Local only | 🌍 Always available |
| **ML Features** | ✅ Full ML | ✅ Full ML |
| **All Parsers** | ✅ 56 parsers | ✅ 56 parsers |

## 🔧 Command Line Options

- `--online`: Force use of online backend, skip local detection
- No flags: Automatic detection with user prompt if localhost unavailable

## ✨ Features

### 🎨 **Modern UI Design**
- **Pixel-perfect match** with siem-tool web app
- **Dark theme** with gradient backgrounds
- **Responsive design** that adapts to window size
- **Professional animations** and hover effects

### 🔍 **Advanced Log Parsing**
- **56+ log formats supported** including Apache, SSH, firewall logs, and more
- **Dynamic parser** for unknown log formats with automatic field detection
- **Drag & drop interface** for easy file uploads
- **Real-time parsing** with animated progress tracking

### 🤖 **ML-Powered Security Analysis**
- **Isolation Forest anomaly detection** algorithm
- **Attack chain correlation** across multiple log sources
- **Risk scoring dashboard** with visual indicators
- **MITRE ATT&CK framework** mapping and recommendations
- **False positive filtering** with confidence scores

### 📊 **Interactive Visualizations**
- **Real-time statistics header** with live updates
- **Advanced filtering** with search and dropdown controls
- **Attack chain visualization** with detailed analysis
- **Timeline analysis** with anomaly highlighting
- **Comprehensive analytics** with charts and insights

## 🏗️ Architecture

```
siem-gui/
├── main.py              # PyWebView desktop application
├── api/
│   └── app.py          # Flask backend API
├── parsers/            # Log parsing engine (ported from siem-tool)
├── ml/                 # ML correlation engine
├── detectors/          # Security alert detection
├── static/             # React frontend assets
└── requirements.txt    # Python dependencies
```

## 📋 Supported Log Types

- **Web Servers**: Apache, Nginx, IIS, Django, Flask, Express
- **Authentication**: SSH, PAM, FTP, SMTP auth
- **Firewalls**: iptables, ufw, firewalld, Cisco ASA, Palo Alto
- **Databases**: MySQL, PostgreSQL, MongoDB, Oracle, MSSQL
- **System**: syslog, journald, audit logs
- **Network**: DHCP, DNS, proxy logs
- **Mail**: Postfix, Sendmail, Dovecot, Exchange

## 🔧 Development

### Running in Development Mode
```bash
# Terminal 1 - Start Flask API
cd siem-gui
python api/app.py

# Terminal 2 - Start PyWebView app
python run.py
```

### Testing the API
```bash
# Health check
curl http://localhost:5000/health

# Parse a log file
curl -X POST http://localhost:5000/parse -F "file=@sample.log"
```

## 🔧 Troubleshooting

### QThread Destruction Warnings
**Issue**: `QThread: Destroyed while thread '' is still running`

**Solution**: This issue has been resolved in the current version. The application now properly manages thread lifecycles with:
- Graceful thread termination with `terminate()` and `wait()`
- Proper Flask server shutdown using Werkzeug
- Qt signal cleanup on application exit
- Resource tracking and cleanup

**Testing**: Run `python test_thread_cleanup.py` to verify clean thread management.

### Backend Connection Issues
**Issue**: Backend status shows "Not Available"

**Solutions**:
- **Offline Backend**: Ensure Flask server can start (check port 5000 availability)
- **Online Backend**: Verify internet connection to `https://freekhana-frontend.pages.dev`
- **Status Refresh**: Click "Refresh Status" button to recheck availability

### WebView Not Loading
**Issue**: WebView container shows placeholder text

**Solutions**:
- Ensure PyWebView is installed: `pip install pywebview`
- Check backend selection - must choose available backend
- Verify backend API is responding (use browser to test URLs)

### Graphics/GPU Compatibility Issues
**Issue**: D3D11 errors, HLSL shader compilation failures, or "Failed to create D3D11 device"

**Symptoms**:
```
Failed to create D3D11 device and context: COM error 0x8007000e
HLSL shader compilation failed
QBackingStoreDefaultCompositor: Failed to build graphics pipeline
```

**Solutions** (try in order):

#### Cross-Platform Diagnostics
```bash
# Linux/macOS
./diagnostics.sh

# Windows
diagnostics.bat
```

#### Compatibility Mode
```bash
# Linux/macOS
./run_compatible.sh

# Windows
run_compatible.bat
```

#### Browser Fallback (Most Compatible)
```bash
# All platforms - opens SIEM in system browser
python main_browser.py
```

**Root Causes**:
- **GPU Memory**: Insufficient GPU memory for Qt WebEngine
- **Graphics Drivers**: Outdated or incompatible graphics drivers
- **Qt WebEngine**: Chromium rendering engine requires modern GPU support
- **Platform-Specific**: Graphics stack differences across platforms

**Fallback Options**:
- **Browser Mode**: Use `main_browser.py` for full functionality via system browser
- **Reduced Features**: Disable WebEngine features in settings
- **Software Rendering**: Force CPU-based rendering (slower but compatible)

## 📄 License

This project is part of the Cyber Chakshu SIEM suite and follows the same open-source licensing terms.