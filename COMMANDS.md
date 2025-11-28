# PenTest Kit - Command Reference Guide

## Quick Commands for certifiedhacker.com Testing

### 1. Censys Reconnaissance (Recommended)
```bash
python main.py censys --target certifiedhacker.com
```
**What it finds:**
- Hosts and IP addresses
- Subdomains from DNS records
- Open ports and services
- SSL/TLS certificates
- Server locations and ASN info

**Free Plan Limits:**
- 1 page of results per search
- Base protocols and certificate data
- Entity lookup and standard queries
- Current host information

### 2. Subdomain Enumeration (Fast)
```bash
python quick-scan.py certifiedhacker.com --subdomain
```
**OR**
```bash
python main.py subdomain --target certifiedhacker.com --threads 10
```

### 3. Vulnerability Scan (Quick)
```bash
python quick-scan.py certifiedhacker.com --vuln
```
**OR**
```bash
python main.py vulnscan --url https://certifiedhacker.com --scan-type quick
```

### 4. Port Scan (Common Ports)
```bash
python quick-scan.py certifiedhacker.com --port
```
**OR**
```bash
python main.py portscan --target certifiedhacker.com --ports 21,22,80,443,3306,8080
```

### 5. Full Reconnaissance (All-in-One)
```bash
python quick-scan.py certifiedhacker.com --recon
```
This runs: Subdomain Enum → Vuln Scan → Port Scan

---

## Interactive Mode
```bash
python quick-scan.py
```
Then select from menu:
1. Full Recon
2. Subdomain Enum
3. Censys Recon (API-based)
4. Port Scan
5. Vuln Scan
6. XSS Test
7. SQLi Test
8. Password Attack
9. Wireless Scan
0. Exit

---

## Advanced Commands

### Censys.io Reconnaissance
```bash
# Comprehensive scan (hosts, subdomains, ports, certificates)
python main.py censys --target certifiedhacker.com

# Works with any domain
python main.py censys --target example.com

# Output saved automatically as: censys_[domain].json
```

**Censys Free Plan Features:**
- Search base protocols & certificate data
- Perform entity lookup and standard queries
- Current host information
- 1 page of results per search
- Limited lookup APIs

### Port Scanning with Nmap Integration
```bash
# Basic port scan with Nmap (includes OS detection and service versioning)
python main.py portscan --target scanme.nmap.org --ports 22,80,443

# Scan common ports (1-1000) with Nmap
python main.py portscan --target certifiedhacker.com --ports 1-1000

# Fast scan specific ports
python main.py portscan --target example.com --ports 21,22,80,443,3306,8080

# Scan all ports (slow, 1-65535)
python main.py portscan --target example.com --ports 1-65535

# Disable Nmap and use fast socket scanning (no OS detection)
python main.py portscan --target example.com --ports 1-1000 --no-nmap

# Custom threads and timeout
python main.py portscan --target example.com --threads 100 --timeout 2

# Save as JSON for detailed results
python main.py portscan --target example.com --output portscan.json
```

**Nmap Features:**
- ✅ OS Detection (Linux, Windows, etc.)
- ✅ Service Version Detection (e.g., "Apache httpd 2.4.7", "OpenSSH 6.6.1")
- ✅ Service Fingerprinting with extra info
- ✅ Protocol Detection (TCP/UDP)
- ✅ Automatic fallback to socket scanning if Nmap fails
- ⚠️ OS detection requires administrator/root privileges

**Output includes:**
```json
{
  "target": "scanme.nmap.org",
  "os_detection": {
    "name": "Linux 4.19 - 5.15",
    "accuracy": "88"
  },
  "open_ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "service": "OpenSSH 6.6.1p1 Ubuntu",
      "product": "OpenSSH",
      "version": "6.6.1p1"
    }
  ]
}
```

### XSS Testing
```bash
# Test GET parameter
python main.py xss --url "https://certifiedhacker.com/search?q=test" --param q --level aggressive

# Test POST parameter
python main.py xss --url "https://certifiedhacker.com/login" --param username --method POST
```

### SQL Injection Testing
```bash
# Test specific parameter
python main.py sqli --url "https://certifiedhacker.com/page?id=1" --param id

# Verbose output
python main.py sqli --url "https://certifiedhacker.com/page?id=1" --param id --verbose
```

### Password Brute Force
```bash
# SSH brute force
python main.py password --target certifiedhacker.com --protocol ssh --username root --wordlist data/wordlists/passwords.txt

# FTP brute force
python main.py password --target certifiedhacker.com --protocol ftp --username admin
```

### Wireless Scanning
```bash
# Scan WiFi networks (requires admin/root)
python main.py wireless --scan

# Scan specific interface
python main.py wireless --interface wlan0 --scan
```

---

## Windows-Specific Commands

### Using BAT wrapper (CMD)
```cmd
pentest.bat subdomain --target certifiedhacker.com --threads 10
pentest.bat portscan --target certifiedhacker.com --ports 80,443
pentest.bat vulnscan --url https://certifiedhacker.com
```

### Using PowerShell wrapper
```powershell
.\pentest.ps1 subdomain --target certifiedhacker.com --threads 10
.\pentest.ps1 portscan --target certifiedhacker.com --ports 80,443
.\pentest.ps1 vulnscan --url https://certifiedhacker.com
```

---

## Output Files

All scan results are automatically saved:
- `subdomains.txt` - Subdomain enumeration results
- `portscan.txt` - Port scanning results
- `vulnscan.json` - Vulnerability scan results (JSON format)
- `dorks.txt` - Google dorking results
- `xss_results.txt` - XSS detection results
- `sqli_results.txt` - SQL injection results

---

## Tips & Tricks

### 1. Quick Full Scan
```bash
python quick-scan.py certifiedhacker.com --recon
```

### 2. Scan Multiple Targets
```bash
# Create a target list
echo certifiedhacker.com > targets.txt
echo demo.certifiedhacker.com >> targets.txt

# Loop through targets (PowerShell)
Get-Content targets.txt | ForEach-Object { python main.py subdomain --target $_ }
```

### 3. Custom Thread Count for Speed
```bash
# Faster (more threads)
python main.py subdomain --target certifiedhacker.com --threads 50

# Slower but safer (less threads)
python main.py subdomain --target certifiedhacker.com --threads 5
```

### 4. Verbose Output
```bash
# Add --verbose to any command
python main.py subdomain --target certifiedhacker.com --verbose
python main.py portscan --target certifiedhacker.com --ports 1-1000 --verbose
```

### 5. Save to Custom Location
```bash
python main.py subdomain --target certifiedhacker.com --output E:\results\subdomains.txt
python main.py portscan --target certifiedhacker.com --output E:\results\ports.txt
```

---

## Common Use Cases

### Case 1: Initial Reconnaissance
```bash
python quick-scan.py certifiedhacker.com --recon
```

### Case 2: Web Application Security Assessment
```bash
# 1. Vuln scan
python main.py vulnscan --url https://certifiedhacker.com --scan-type full

# 2. Dork for files
python main.py dork --target certifiedhacker.com --type files

# 3. Test for XSS/SQLi on discovered endpoints
python main.py xss --url "https://certifiedhacker.com/search?q=test" --param q
python main.py sqli --url "https://certifiedhacker.com/page?id=1" --param id
```

### Case 3: Network Penetration Testing
```bash
# 1. Port scan
python main.py portscan --target certifiedhacker.com --ports 1-65535 --threads 100

# 2. Service-specific attacks on open ports
# If SSH (22) is open:
python main.py password --target certifiedhacker.com --protocol ssh --username admin

# If FTP (21) is open:
python main.py password --target certifiedhacker.com --protocol ftp --username ftp
```

---

## Example Results

### Subdomain Scan Results (certifiedhacker.com)
Found **51 unique subdomains**:
- autodiscover.certifiedhacker.com
- blog.certifiedhacker.com
- cpanel.certifiedhacker.com
- demo.certifiedhacker.com
- mail.certifiedhacker.com
- soc.certifiedhacker.com
- webmail.certifiedhacker.com
- [... and 44 more]

### Port Scan Results
Found **4 open ports**:
- Port 21 (FTP)
- Port 22 (SSH)
- Port 80 (HTTP)
- Port 443 (HTTPS)

### Vulnerability Scan Results
Found **12 vulnerabilities**:
- 5 Medium severity (Directory listing, CSRF)
- 6 Low severity (Missing security headers)
- 1 Info (Server version disclosure)

---

## Legal Disclaimer

⚠️ **IMPORTANT**: Only test systems you own or have explicit written permission to test.
Unauthorized penetration testing is illegal.

```bash
# Always read the disclaimer first
python main.py disclaimer
```

---

## Getting Help

```bash
# Main help
python main.py --help

# Module-specific help
python main.py subdomain --help
python main.py portscan --help
python main.py vulnscan --help
python main.py xss --help
python main.py sqli --help
python main.py dork --help
python main.py password --help
python main.py wireless --help
```
