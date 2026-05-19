# Cyber Chakshu SIEM Desktop Application

**Modern desktop SIEM tool with PySide6 GUI and embedded WebView, featuring all 56+ log parsers and ML-powered analysis.**

## 🚀 Quick Start

### Installation
```bash
cd webview-gui
pip install -r requirements.txt
```

### Launch
```bash
python run.py
```

## ✨ Features

### 🎨 **Modern PySide6 GUI**
- **Native desktop interface** with dark theme
- **Real-time backend switching** between local and online
- **Embedded WebView** for seamless React UI integration
- **Backend status monitoring** and automatic detection

### 🔍 **Complete Log Analysis Engine**
- **56+ log format parsers** from web application
- **ML-powered anomaly detection** with Isolation Forest
- **Attack chain correlation** across multiple sources
- **MITRE ATT&CK framework** mapping

### 🌐 **Flexible Backend Options**
- **Automatic detection**: Local → Online fallback
- **Manual switching**: Choose between backends anytime
- **Local backend**: Start/stop Flask server from GUI
- **Online backend**: Always available at `https://freekhana-frontend.pages.dev`

### 📊 **Interactive Features**
- **Real-time status updates** for backend availability
- **One-click backend switching** without restart
- **Progress indicators** and error handling
- **Modern dark theme** matching the web app

## 🏗️ Architecture

```
Cyber Chakshu SIEM Desktop
├── PySide6 GUI (Native Interface)
│   ├── Backend Selection Panel
│   ├── Status Monitoring
│   └── WebView Container
│
├── Embedded WebView (React Frontend)
│   ├── Same UI as web app
│   ├── Interactive visualizations
│   └── Real-time updates
│
└── Backend System
    ├── Local Flask API (optional)
    └── Online API (always available)
```

## 📋 Supported Log Formats

### Database (14 parsers)
MySQL, PostgreSQL, Oracle, SQL Server, MongoDB

### Web Servers (10 parsers)
Apache, Nginx, IIS, Django, Flask, Laravel, Express, Gunicorn, Uvicorn, Rails

### Authentication (8 parsers)
SSH, PAM, sudo, su, FTP, vsftpd

### Firewalls (12 parsers)
iptables, UFW, nftables, firewalld, Windows Firewall, Palo Alto, FortiGate, Cisco ASA, Check Point, AWS VPC, Azure NSG, GCP VPC

### Mail (5 parsers)
Postfix, Sendmail, Exim, Dovecot, Exchange

### System (7 parsers)
syslog, systemd, kernel, audit, package, cron, daemon

## 🎯 How It Works

1. **Launch Application**: PySide6 GUI starts and checks backend availability
2. **Backend Selection**: Automatically selects best available backend
3. **WebView Loading**: React frontend loads in embedded container
4. **Real-time Switching**: Change backends without restarting app
5. **Clean Operation**: Proper thread management prevents QThread warnings
6. **Full Functionality**: All web app features available in desktop

## 🔧 Technical Details

- **GUI Framework**: PySide6 (Qt for Python)
- **Web Engine**: PyWebView with embedded browser
- **Backend API**: Flask with CORS support
- **Frontend**: React + TypeScript (same as web app)
- **ML Engine**: scikit-learn for anomaly detection
- **Platform**: Windows (cross-platform with Qt)

## 📝 Requirements

- Python 3.8+
- PySide6
- PyWebView
- Flask + Flask-CORS
- NumPy + scikit-learn

## 🎉 Benefits

- **Native Desktop Experience**: No browser window, proper desktop integration
- **Always Available**: Online backend ensures app works anywhere
- **Modern UI**: Same beautiful interface as web application
- **Full Feature Set**: All 56 parsers and ML analysis included
- **Real-time Switching**: Change backends on the fly

## ⚠️ Legacy: PySide6 Implementation

**Location**: `pyside6-gui/` (Deprecated)
**Technology**: PySide6 (Qt for Python)
**Status**: ❌ Outdated, Limited Features

### Why Avoid This?
- **Outdated UI**: Basic Qt interface, not modern
- **Limited Features**: Only basic parsers and ML
- **Windows Only**: PySide6 has platform limitations
- **Not Maintained**: No longer actively developed

### Directory Structure

```
siem-gui/
├── README.md             # This file
└── webview-gui/          # ⭐ MAIN APPLICATION - PySide6 GUI with embedded WebView
    ├── main.py           # PySide6 GUI with embedded WebView
    ├── run.py            # Launcher script
    ├── api/              # Flask backend (auto-managed)
    ├── parsers/          # 56+ log parsers
    ├── ml/               # ML correlation engine
    ├── detectors/        # Security alerts
    ├── static/           # React frontend assets
    ├── requirements.txt  # Python dependencies
    └── README.md         # Detailed documentation
```

## 📊 Feature Comparison

| Feature | PySide6 + WebView | Legacy PySide6 |
|---------|----------------|---------|
| **UI Modernity** | ⭐⭐⭐⭐⭐ React, responsive | ⭐⭐ Basic Qt interface |
| **Log Parsers** | ⭐⭐⭐⭐⭐ 56+ complete | ⭐⭐ Limited (basic) |
| **ML Features** | ⭐⭐⭐⭐⭐ Full anomaly detection | ⭐⭐⭐ Basic isolation forest |
| **Cross-Platform** | ⭐⭐⭐⭐⭐ Windows/macOS/Linux | ⭐⭐ Windows only |
| **Maintenance** | ⭐⭐⭐⭐⭐ Active | ❌ None |
| **Setup Complexity** | ⭐⭐⭐⭐ Simple | ⭐⭐⭐ Moderate |

## 🎯 Which One Should You Use?

### Use `webview-gui/` if you want:
- Modern, professional UI matching the web app
- Complete feature set with all log parsers
- Cross-platform compatibility
- Active development and support
- Future updates and improvements

### Only use `pyside6-gui/` if you:
- Have specific PySide6/Qt requirements
- Need to run on older Windows systems
- Are doing legacy maintenance (not recommended for new projects)

## 🔧 System Requirements

### PySide6 + WebView (Current)
- Python 3.8+
- PySide6, PyWebView, Flask, Flask-CORS
- NumPy, scikit-learn (for ML features)
- Works on Windows, macOS, Linux

### PySide6 (Legacy)
- Python 3.8+
- PySide6, pandas, numpy, scikit-learn
- Windows only (limited cross-platform support)

## 📝 Contributing

For new development, please contribute to the `webview-gui/` implementation. The PySide6 implementation is legacy code and should not receive new features.

## 📄 License

This project is part of the Cyber Chakshu SIEM suite and follows the same open-source licensing terms.