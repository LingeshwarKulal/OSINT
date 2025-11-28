# Nmap Integration Guide

## Overview

The PenTest Toolkit now includes **Nmap integration** for advanced port scanning with OS detection and service version fingerprinting.

## Features

### ✅ What's New

- **OS Detection**: Identify target operating system (Linux, Windows, etc.)
- **Service Version Detection**: Get detailed service versions (e.g., "Apache httpd 2.4.7", "OpenSSH 8.7")
- **Advanced Fingerprinting**: Product names, versions, and extra information
- **Automatic Fallback**: Falls back to fast socket scanning if Nmap is unavailable
- **Smart Detection**: Automatically detects if Nmap is installed

### 🔍 Comparison

| Feature | Socket Scanning (--no-nmap) | Nmap Scanning (default) |
|---------|----------------------------|-------------------------|
| Speed | ⚡ Very Fast | 🐢 Slower (more thorough) |
| OS Detection | ❌ No | ✅ Yes (requires admin) |
| Service Versions | ❌ Basic names only | ✅ Full version detection |
| Accuracy | ⚠️ Basic | ✅ High accuracy |
| Privileges | 👤 User | 🔐 Admin (for OS detection) |

## Installation

### Prerequisites

1. **Nmap** must be installed on your system:

**Windows:**
```bash
# Download from: https://nmap.org/download.html
# Or use Chocolatey:
choco install nmap
```

**Linux:**
```bash
sudo apt-get install nmap  # Debian/Ubuntu
sudo yum install nmap      # CentOS/RHEL
```

**macOS:**
```bash
brew install nmap
```

2. **Python library** (already in requirements.txt):
```bash
pip install python-nmap
```

## Usage Examples

### Basic Scan with Nmap (Default)
```bash
python main.py portscan --target scanme.nmap.org --ports 1-1000
```

### Scan Specific Ports
```bash
python main.py portscan --target example.com --ports 21,22,80,443,3306,8080
```

### Fast Socket Scan (No Nmap)
```bash
python main.py portscan --target example.com --ports 1-65535 --no-nmap --threads 200
```

### Save Detailed Results as JSON
```bash
python main.py portscan --target example.com --ports 1-1000 --output detailed_scan.json
```

## Example Output

### Console Output
```
🔍 Starting Nmap scan on certifiedhacker.com...
Port range: 21,22,80,443,3306,8080
Options: Service version detection (-sV) + OS detection (-O)

✓ OS Detection: Linux 3.10 - 4.11 (Accuracy: 86%)

╭─────────────── 🖥️  Operating System Detection ───────────────╮
│ Linux 3.10 - 4.11                                           │
│ Accuracy: 86%                                               │
╰─────────────────────────────────────────────────────────────╯

              🔍 Open Ports on certifiedhacker.com
┏━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃     Port ┃ Protocol   ┃ State      ┃ Service               ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│       21 │ tcp        │ open       │ Pure-FTPd             │
│       22 │ tcp        │ open       │ OpenSSH 8.7           │
│       80 │ tcp        │ open       │ Apache httpd          │
│      443 │ tcp        │ open       │ Apache httpd          │
│     3306 │ tcp        │ open       │ MySQL 5.7.44-48       │
└──────────┴────────────┴────────────┴───────────────────────┘

✓ Found 5 open ports
ℹ Service version detected on 5 ports
```

### JSON Output
```json
{
    "target": "certifiedhacker.com",
    "total_ports_scanned": 5,
    "open_ports": [
        {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "OpenSSH 8.7 (protocol 2.0)",
            "product": "OpenSSH",
            "version": "8.7",
            "extrainfo": "protocol 2.0"
        },
        {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "Apache httpd",
            "product": "Apache httpd",
            "version": "",
            "extrainfo": ""
        },
        {
            "port": 3306,
            "protocol": "tcp",
            "state": "open",
            "service": "MySQL 5.7.44-48",
            "product": "MySQL",
            "version": "5.7.44-48",
            "extrainfo": ""
        }
    ],
    "os_detection": {
        "name": "Linux 3.10 - 4.11",
        "accuracy": "86",
        "line": "70574"
    },
    "scan_config": {
        "threads": 50,
        "timeout": 1,
        "nmap_enabled": true
    }
}
```

## Command-Line Options

```bash
python main.py portscan --help
```

**Options:**
- `--target, -t`: Target IP or domain (required)
- `--ports, -p`: Port range (e.g., "1-1000", "80,443,8080")
- `--output, -o`: Output file (.txt or .json)
- `--threads`: Number of threads for socket scanning (default: 50)
- `--timeout`: Connection timeout in seconds (default: 1)
- `--nmap/--no-nmap`: Enable/disable Nmap (default: enabled)
- `--verbose, -v`: Verbose output

## Troubleshooting

### 1. "Nmap not available" Warning
```
⚠ Nmap not available, falling back to socket scanning
```
**Solution:** Install Nmap from https://nmap.org/download.html

### 2. OS Detection Requires Admin Privileges
```
⚠ OS detection requires administrator privileges, continuing without it...
```
**Solution:** Run as administrator/root:
```bash
# Windows (Run PowerShell as Administrator)
python main.py portscan --target example.com --ports 1-1000

# Linux/macOS
sudo python main.py portscan --target example.com --ports 1-1000
```

### 3. Scan is Slow
Nmap is more thorough but slower than socket scanning.

**Solutions:**
- Reduce port range: `--ports 21,22,80,443` instead of `--ports 1-65535`
- Use socket scanning: `--no-nmap --threads 200`
- Scan fewer hosts at once

## Performance Tips

### Fast Scan (Common Ports)
```bash
python main.py portscan --target example.com --ports 21,22,80,443,3306,8080
```
⏱️ ~10-20 seconds

### Comprehensive Scan (1-1000)
```bash
python main.py portscan --target example.com --ports 1-1000
```
⏱️ ~2-5 minutes

### Full Scan (1-65535)
```bash
python main.py portscan --target example.com --ports 1-65535 --no-nmap --threads 500
```
⏱️ ~5-10 minutes (socket scanning recommended)

## Security Considerations

⚠️ **Authorization Required**: Only scan systems you have explicit permission to test.

⚠️ **Rate Limiting**: Some networks may detect and block port scanning.

⚠️ **Legal Compliance**: Unauthorized port scanning may be illegal in your jurisdiction.

✅ **Recommended Test Targets:**
- `scanme.nmap.org` - Official Nmap test server
- Your own infrastructure
- Bug bounty programs with explicit permission

## Integration with Other Modules

### 1. Full Reconnaissance Workflow
```bash
# Step 1: Subdomain enumeration
python main.py subdomain --target example.com

# Step 2: Netlas intelligence
python main.py netlas --target example.com

# Step 3: Advanced port scanning with Nmap
python main.py portscan --target example.com --ports 1-1000

# Step 4: Vulnerability scanning
python main.py vulnscan --url https://example.com
```

### 2. Quick Scan Mode
```bash
python quick-scan.py example.com --recon
```
This automatically runs subdomain → vuln → port scanning

## Technical Details

### Nmap Arguments Used
```
-sV                   # Service version detection
-O                    # OS detection (requires admin)
-T4                   # Faster timing template
--version-intensity 5 # Aggressive version detection
```

### Fallback Behavior
1. First tries Nmap scan with OS detection (-sV -O)
2. If OS detection fails (no admin), retries without -O
3. If Nmap is unavailable, uses fast socket scanning
4. Never fails - always returns results

## Version Information

- **Toolkit Version**: 1.0.0
- **Nmap Version Required**: 7.80+
- **python-nmap Version**: 0.7.1+

## Support

For issues or questions:
1. Check `COMMANDS.md` for command reference
2. Review `README.md` for setup instructions
3. See test results in `output/` directory

---

**Happy Hacking! 🔓**
*Remember: Always practice responsible disclosure and obtain proper authorization.*
