# Installation Guide

## Requirements

- Python 3.8 or higher
- pip package manager
- Git (for installation from source)

## Quick Install

### From GitHub (Current Method)
```bash
# Clone the repository
git clone https://github.com/SPR-k-3/SPRk-3-platform-.git
cd SPRk-3-platform-

# Install dependencies
pip install -r requirements.txt

# Verify installation
python sprk3_engine.py --version
```

### Using pip (Coming Soon)
```bash
pip install sprk3-scanner
```

## Platform Support

- ✅ Linux (Ubuntu, Debian, RHEL, etc.)
- ✅ macOS (10.14+)
- ✅ Windows (10/11 with Python)
- ✅ GitHub Actions

## Troubleshooting

### ImportError
```bash
pip install --upgrade -r requirements.txt
```

### Permission Denied
```bash
chmod +x sprk3_engine.py
```

## Verification

Test the installation:
```bash
python sprk3_engine.py examples/
```
