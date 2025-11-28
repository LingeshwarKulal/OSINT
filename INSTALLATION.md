# 🚀 Installation Guide - Penetration Testing Toolkit

## Prerequisites

### System Requirements:
- **Python:** 3.10 or higher
- **Operating System:** Windows 10+, Linux (Ubuntu 20.04+, Kali), macOS 11+
- **RAM:** 4GB minimum, 8GB recommended
- **Disk Space:** 500MB for installation + space for output files

### Required Permissions:
- Some modules (port scanning, wireless) may require administrator/root privileges
- Network access for external API calls (Google, crt.sh, etc.)

---

## Step-by-Step Installation

### 1. Clone or Download the Repository

```bash
# If using Git
git clone <repository-url>
cd newpro

# Or simply navigate to the downloaded folder
cd e:\newpro
```

### 2. Create Virtual Environment (Recommended)

**Windows:**
```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\activate
```

**Linux/macOS:**
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

### 3. Install Dependencies

```bash
# Upgrade pip first
pip install --upgrade pip

# Install all requirements
pip install -r requirements.txt
```

### 4. Run Setup Script

```bash
python setup.py
```

This will:
- Create necessary directories (`data`, `logs`, `output`)
- Verify installation
- Display quick start commands

### 5. Verify Installation

```bash
# Check if toolkit is working
python main.py --help

# Display legal disclaimer
python main.py disclaimer

# Test a simple command (requires internet)
python main.py subdomain --target example.com
```

---

## Platform-Specific Installation

### Windows

**Prerequisites:**
```powershell
# Install Python from python.org (3.10+)
# Ensure Python is added to PATH

# Verify installation
python --version
pip --version
```

**Installation:**
```powershell
cd e:\newpro
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python setup.py
```

**Common Issues:**
- **Microsoft Visual C++ required:** Install from [Microsoft's website](https://visualstudio.microsoft.com/downloads/)
- **Long path error:** Enable long paths in Windows settings

---

### Linux (Ubuntu/Debian)

**Prerequisites:**
```bash
# Update package list
sudo apt update

# Install Python and dependencies
sudo apt install python3 python3-pip python3-venv

# Install additional tools (optional)
sudo apt install nmap aircrack-ng
```

**Installation:**
```bash
cd ~/newpro
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python setup.py
```

**Permissions:**
```bash
# Some modules require root
sudo python main.py portscan --target example.com
sudo python main.py wireless --interface wlan0 --scan
```

---

### Linux (Kali Linux)

Kali Linux comes with most tools pre-installed:

```bash
cd ~/newpro
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python setup.py
```

---

### macOS

**Prerequisites:**
```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.10

# Verify installation
python3 --version
```

**Installation:**
```bash
cd ~/newpro
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python setup.py
```

---

## Troubleshooting

### Issue: "Module not found" error

**Solution:**
```bash
# Reinstall all dependencies
pip install -r requirements.txt --force-reinstall

# Or install specific missing module
pip install <module-name>
```

### Issue: Permission denied on Linux

**Solution:**
```bash
# Run with sudo for network operations
sudo python main.py portscan --target example.com

# Or add your user to required groups
sudo usermod -aG netdev $USER
```

### Issue: SSL certificate errors

**Solution:**
```bash
# Disable SSL verification (not recommended for production)
export PYTHONHTTPSVERIFY=0

# Or install certificates
pip install --upgrade certifi
```

### Issue: Scapy doesn't work on Windows

**Solution:**
```powershell
# Install Npcap
# Download from https://npcap.com/
# Install with "WinPcap API-compatible mode" enabled
```

### Issue: DNS resolution fails

**Solution:**
```bash
# Check DNS servers in config.yaml
# Edit and change to:
dns_servers:
  - "8.8.8.8"
  - "1.1.1.1"
```

### Issue: Import errors with paramiko

**Solution:**
```bash
# Install cryptography dependencies
pip install cryptography paramiko --upgrade
```

---

## Optional Dependencies

### For Enhanced Features:

**Selenium (for JavaScript rendering):**
```bash
pip install selenium
# Also install ChromeDriver or GeckoDriver
```

**Playwright (alternative browser automation):**
```bash
pip install playwright
playwright install
```

**Additional wordlists:**
```bash
# Download SecLists
git clone https://github.com/danielmiessler/SecLists.git data/SecLists
```

**Nmap integration:**
```bash
# Windows: Download from nmap.org
# Linux:
sudo apt install nmap

# macOS:
brew install nmap
```

---

## Configuration

### 1. Edit Config File

```bash
# Open config.yaml in your editor
nano config.yaml    # Linux/macOS
notepad config.yaml # Windows
```

### 2. Common Configuration Changes

```yaml
# Increase threads for faster scanning
port_scanner:
  threads: 100

# Add custom DNS servers
subdomain:
  dns_servers:
    - "8.8.8.8"
    - "1.1.1.1"
    - "208.67.222.222"

# Adjust timeouts
general:
  timeout: 15
```

---

## Updating

### Update Python Packages:
```bash
pip install -r requirements.txt --upgrade
```

### Pull Latest Changes (if using Git):
```bash
git pull origin main
pip install -r requirements.txt --upgrade
```

---

## Uninstallation

### Remove Virtual Environment:
```bash
# Deactivate first
deactivate

# Remove directory
rm -rf venv  # Linux/macOS
rmdir /s venv  # Windows
```

### Remove All Files:
```bash
cd ..
rm -rf newpro  # Linux/macOS
rmdir /s newpro  # Windows
```

---

## Docker Installation (Alternative)

### Create Dockerfile:
```dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "main.py"]
```

### Build and Run:
```bash
# Build image
docker build -t pentest-toolkit .

# Run container
docker run -it --rm pentest-toolkit --help
```

---

## Testing Installation

### Run Test Suite:
```bash
# Test subdomain enumeration
python main.py subdomain --target example.com

# Test port scanning (requires target)
python main.py portscan --target scanme.nmap.org --ports 80,443

# Test vulnerability scanner
python main.py vulnscan --url https://example.com

# Display help for all commands
python main.py --help
```

---

## First Run Checklist

- [ ] Python 3.10+ installed
- [ ] Virtual environment activated
- [ ] All dependencies installed
- [ ] Setup script executed successfully
- [ ] Config file reviewed
- [ ] Legal disclaimer read
- [ ] Authorization obtained for testing
- [ ] Test command executed successfully

---

## Getting Help

### Built-in Help:
```bash
# General help
python main.py --help

# Module-specific help
python main.py subdomain --help
python main.py portscan --help
python main.py xss --help
```

### Documentation:
- **README.md** - Project overview
- **QUICKSTART.md** - Usage examples
- **PROJECT_SUMMARY.md** - Complete feature list
- **PRD.md** - Technical specifications

### Support:
- Check logs in `logs/` directory
- Review output in `output/` directory
- Enable verbose mode: `--verbose`

---

## Next Steps

1. ✅ Read the QUICKSTART.md guide
2. ✅ Review the legal disclaimer
3. ✅ Get proper authorization
4. ✅ Start with reconnaissance modules
5. ✅ Practice on authorized targets only

---

## 🎉 Installation Complete!

Your Penetration Testing Toolkit is ready to use!

```bash
# Start testing
python main.py --help
```

**Remember: Always test ethically and legally!** 🔒

---

## Quick Reference Card

```bash
# Subdomain scan
python main.py subdomain -t example.com

# Port scan
python main.py portscan -t example.com -p 1-1000

# Google dorks
python main.py dork -t example.com --type all

# Vulnerability scan
python main.py vulnscan -u https://example.com

# XSS test
python main.py xss -u "https://example.com/search?q=test"

# SQL injection test
python main.py sqli -u "https://example.com/page?id=1"

# Password attack
python main.py password -t ssh://192.168.1.1 -u admin -w passwords.txt

# Wireless scan
python main.py wireless -i wlan0 --scan
```

---

**Happy Ethical Hacking! 🚀**
