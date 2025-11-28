# Nmap Port Scanner - Quick Reference

## Basic Commands

### 1. Standard Nmap Scan (Recommended)
```bash
python main.py portscan --target example.com --ports 1-1000
```
- Includes OS detection
- Service version detection
- Requires: Nmap installed

### 2. Quick Service Scan (Common Ports)
```bash
python main.py portscan --target example.com --ports 21,22,80,443,3306,8080
```
⏱️ ~10-20 seconds

### 3. Fast Socket Scan (No Nmap)
```bash
python main.py portscan --target example.com --ports 1-65535 --no-nmap --threads 500
```
⚡ Very fast, but no version detection

### 4. Save as JSON (Detailed Output)
```bash
python main.py portscan --target example.com --ports 1-1000 --output results.json
```

## What You Get

### With Nmap (Default)
✅ OS Detection: "Linux 3.10 - 4.11" (86% accuracy)  
✅ Service Versions: "OpenSSH 8.7", "Apache httpd 2.4.7"  
✅ Product Info: Detailed service identification  
✅ Protocol: TCP/UDP detection  
⚠️ Slower: ~2-5 minutes for 1000 ports  

### Without Nmap (--no-nmap)
⚡ Speed: ~30 seconds for 1000 ports  
✅ Open Port Detection  
✅ Basic Service Names: "SSH", "HTTP", "MySQL"  
❌ No OS Detection  
❌ No Version Detection  

## Output Format

### Console Display
```
🔍 Starting Nmap scan on certifiedhacker.com...
✓ OS Detection: Linux 3.10 - 4.11 (Accuracy: 86%)

╭─────────────── 🖥️  Operating System Detection ───────────────╮
│ Linux 3.10 - 4.11                                           │
│ Accuracy: 86%                                               │
╰─────────────────────────────────────────────────────────────╯

              🔍 Open Ports on certifiedhacker.com
┏━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃     Port ┃ Protocol   ┃ State      ┃ Service               ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│       22 │ tcp        │ open       │ OpenSSH 8.7           │
│       80 │ tcp        │ open       │ Apache httpd          │
│     3306 │ tcp        │ open       │ MySQL 5.7.44-48       │
└──────────┴────────────┴────────────┴───────────────────────┘

✓ Found 3 open ports
ℹ Service version detected on 3 ports
```

### JSON Format
```json
{
  "target": "certifiedhacker.com",
  "os_detection": {
    "name": "Linux 3.10 - 4.11",
    "accuracy": "86"
  },
  "open_ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "service": "OpenSSH 8.7 (protocol 2.0)",
      "product": "OpenSSH",
      "version": "8.7",
      "extrainfo": "protocol 2.0"
    }
  ],
  "scan_config": {
    "nmap_enabled": true
  }
}
```

## Command Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target, -t` | Target IP or domain | Required |
| `--ports, -p` | Port range or list | 1-1000 |
| `--output, -o` | Output file | portscan.txt |
| `--threads` | Thread count (socket mode) | 50 |
| `--timeout` | Connection timeout (seconds) | 1 |
| `--nmap` | Enable Nmap scanning | true |
| `--no-nmap` | Disable Nmap, use sockets | false |
| `--verbose, -v` | Verbose output | false |

## Common Scenarios

### Scenario 1: Initial Recon
```bash
# Find common services
python main.py portscan --target example.com --ports 21,22,80,443,3306,8080
```

### Scenario 2: Full Port Scan
```bash
# Comprehensive but slow
python main.py portscan --target example.com --ports 1-65535 --no-nmap --threads 1000
```

### Scenario 3: Specific Service Audit
```bash
# Web servers only
python main.py portscan --target example.com --ports 80,443,8080,8443

# Database servers
python main.py portscan --target example.com --ports 1433,3306,5432,27017
```

### Scenario 4: Network Sweep
```bash
# Scan multiple hosts (use a script)
for host in $(cat targets.txt); do
    python main.py portscan --target $host --ports 1-1000 --output "scan_$host.json"
done
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Nmap not available" | Install from nmap.org/download |
| "OS detection requires admin" | Run as Administrator/root |
| Scan is slow | Use fewer ports or --no-nmap |
| No services detected | Check firewall, try --verbose |

## Performance Guide

| Port Count | Method | Time | Command |
|------------|--------|------|---------|
| 6-10 ports | Nmap | ~15s | `--ports 80,443` |
| 100 ports | Nmap | ~1min | `--ports 1-100` |
| 1000 ports | Nmap | ~3min | `--ports 1-1000` |
| 1000 ports | Socket | ~30s | `--ports 1-1000 --no-nmap` |
| 65535 ports | Socket | ~10min | `--ports 1-65535 --no-nmap --threads 1000` |

## Integration Examples

### With Quick-Scan Menu
```bash
python quick-scan.py
# Select option 4: Port Scan
```

### Combined Workflow
```bash
# 1. Subdomain discovery
python main.py subdomain --target example.com

# 2. Port scan each subdomain
python main.py portscan --target sub1.example.com --ports 1-1000

# 3. Vulnerability scan
python main.py vulnscan --url https://sub1.example.com
```

### Automated Script
```bash
# Create batch scan script
echo 'python main.py portscan --target $1 --ports 1-1000' > scan.sh
chmod +x scan.sh
./scan.sh example.com
```

## Safe Testing Targets

✅ **Authorized:**
- `scanme.nmap.org` - Official Nmap test server
- Your own servers
- Bug bounty targets with permission

❌ **Never Scan:**
- Government systems
- Banking/financial services
- Healthcare systems
- Systems without explicit permission

## Next Steps

After port scanning:
1. Identify vulnerable services
2. Run targeted exploits (authorized only)
3. Check CVE databases for versions found
4. Document findings
5. Remediate vulnerabilities

---

**Quick Help:**
```bash
python main.py portscan --help
```

**Full Documentation:**
- `NMAP_INTEGRATION.md` - Complete guide
- `COMMANDS.md` - All commands
- `README.md` - Setup instructions
