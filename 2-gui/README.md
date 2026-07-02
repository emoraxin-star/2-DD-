# LiberTea - Complete GUI Solution

This directory contains **two complementary GUI interfaces** for accessing LiberTea v414 analysis data:

- **Web GUI** (FastAPI + React/HTML) - Immediate, cross-platform access
- **ImGui Desktop** (C++17 + Native Windows) - High-performance, native experience

Both GUIs provide access to:
- All 100+ project files
- 11,736 extracted strings
- 73 hook patterns
- 21 analysis logs
- Documentation (2.5 MB)
- Scripts & tools

## Quick Start

### Option 1: Web GUI (Recommended for most users)
```bash
# Navigate to project directory
C:\Users\emora\OneDrive\Desktop\2

# Install dependencies
pip install -r gui/requirements.txt

# Run web server
python gui/backend.py

# Access in browser:
http://127.0.0.1:8080
```

### Option 2: ImGui Desktop (Native Windows)
```bash
# Navigate to project directory
cd C:\Users\emora\OneDrive\Desktop\2

# Create and build in separate folder
mkdir build_gui
cd build_gui
cmake -G "Visual Studio 17 2022" -A x64 ..
# OR use CMake GUI (configure)
cmake --build . --config Release

# Run native application
Release\\LiberTeaBrowser.exe
```

## Why Both GUIs?

### Web GUI Advantages:
- ✅ **Immediate deployment** - no compilation needed
- ✅ **Cross-platform** - works on Windows, Mac, Linux
- ✅ **Easy setup** - single Python command
- ✅ **Network access** - accessible from anywhere
- ✅ **Updates** - always on latest version

### ImGui Desktop Advantages:
- ✅ **Maximum performance** - native OpenGL rendering
- ✅ **Full native integration** - Windows feel + system tray
- ✅ **Offline capability** - one-click standalone application
- ✅ **Better for frequent use** - responsive, dedicated UI
- ✅ **Zero dependencies** - just one executable

## Feature Comparison

| Feature | Web GUI | ImGui Desktop |
|---------|---------|---------------|
| **Setup Time** | 5 minutes | 2-3 hours |
| **Platform** | Cross-platform | Windows only |
| **Performance** | Good (multi-threaded) | Excellent (native) |
| **Network Access** | Yes, HTTP/REST | No (local) |
| **Offline** | Limited (server needed) | Yes (single exe) |
| **Updates** | Automatic (pip) | Manual (rebuild) |

## What's Included

### Web GUI Structure:
```
gui/
├── backend.py          # FastAPI server (Python)
├── index.html          # HTML/JS frontend
└── requirements.txt    # Python dependencies
```

### ImGui Desktop Structure:
```
src/
├── main_simple.cpp    # Entry point (C++)
├── browser.h          # Core UI logic
└── file_loader.cpp    # Data access (shared)

build/
├── CMake configuration
└── Compiled executable (Release/LiberTeaBrowser.exe)
```

## Data Access

Both GUIs access the same project data:

### Available Data Sources:
- `data/all_strings.txt` - 11,736 extracted strings
- `data/patterns_extracted.json` - 73 hook patterns
- `logs/agent*.txt` - 21 analysis logs
- `docs/**/*.txt` - Full documentation
- `scripts/**/*.py/.ps1` - Analysis tools
- Binary files (.bin/.dll) - Game data

### Unified Data Model:
```json
{
  "file_browser": {
    "root_files": ["LIBERTEA.DLL", "README.md", ...],
    "data_files": [".text_decompressed.bin", ...],
    "documentation": ["01_binary_identity/*.txt"],
    "logs": ["agent1_integrity_scan.txt", ...],
    "scripts": ["scripts/agent1_scan.ps1", ...]
  },
  "content_viewer": {
    "strings": ["0001D7: L$ SUVWE", ...],
    "patterns": [{"offset": 1054744, "signature": "48 89 5C 24..."}],
    "binary_files": ["loaded as hex dump"]
  }
}
```

## Development Notes

### Web GUI Development:
- **Language**: Python 3.8+ + FastAPI
- **Framework**: HTML/JavaScript (Material Design)
- **Deployment**: pip install + uvicorn
- **Testing**: Natural testing with network access

### ImGui Desktop Development:
- **Language**: C++17 with static CRT
- **Framework**: Dear ImGui 1.91.5 + OpenGL
- **Platform**: Win32 + OpenGL3
- **Build**: CMake + Visual Studio/MSVC

## Migration Guide

### From Web to ImGui:
1. Uninstall current Python setup (optional)
2. Install Visual Studio 2019+ Community Edition
3. Clone current repository
4. Follow ImGui build instructions above

### From ImGui to Web:
1. Install Python 3.8+
2. Run pip install -r gui/requirements.txt
3. Launch python gui/backend.py

## Future Enhancements

### Web GUI Plans:
- [ ] WebSocket real-time updates
- [ ] Collaborative annotation
- [ ] Advanced search with AI suggestions
- [ ] Export tools (PDF, CSV)
- [ ] Mobile-responsive design

### ImGui Desktop Plans:
- [ ] System tray integration
- [ ] Dock integration (Taskbar/Start Menu)
- [ ] Advanced visualizations (graphs, charts)
- [ ] Performance profiling tools
- [ ] Script debugging support

## Troubleshooting

### Web GUI Issues:
```
# "Connection refused" error
cd /path/to/project
set FLASK_ENV=development
python gui/backend.py
```

### ImGui Build Issues:
```
# CMake GeneratorError
cd build_gui
rmdir /s /q CMakeCache.txt CMakeFiles
rd /s /q build_simple
rmdir /s /q build_simple
```

## Support

**For immediate deployment:** Use Web GUI - it's production-ready now.

**For native development:** ImGui requires C++ environment setup.

**Project dependencies:**
- Web GUI: Python 3.8+, pip
- ImGui: Visual Studio 2019+, CMake

Both GUIs serve the same LiberTea v414 analysis needs - just with different UX and deployment strategies.

---

**Quick Usage:**
```bash
# Quick access - just 2 commands!
pip install -r gui/requirements.txt
python gui/backend.py
```

This gives you a fully functional LiberTea browser within 60 seconds of environment setup.

---

*Both GUIs are actively maintained and provide the same LiberTea v414 reverse engineering analysis capabilities.*
*