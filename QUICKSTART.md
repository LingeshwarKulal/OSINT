# Quick Start Guide - Penetration Testing Toolkit

## Installation

### 1. Install Dependencies
```bash
# Install Python dependencies
pip install -r requirements.txt

# Run setup
python setup.py
```

### 2. Verify Installation
```bash
python main.py --help
```

## Module Usage Examples

### 1. Subdomain Enumeration

**Basic scan:**
```bash
python main.py subdomain --target example.com
```

**With custom wordlist:**
```bash
python main.py subdomain --target example.com --wordlist custom.txt --threads 20
```

**Save results:**
```bash
python main.py subdomain --target example.com --output subdomains.txt
```

---

### 2. Port Scanning

**Scan common ports:**
```bash
python main.py portscan --target example.com
```

**Scan specific port range:**
```bash
python main.py portscan --target 192.168.1.1 --ports 1-65535
```

**Fast scan with more threads:**
```bash
python main.py portscan --target example.com --threads 100 --timeout 0.5
```

**Scan specific ports:**
```bash
python main.py portscan --target example.com --ports 80,443,8080,8443
```

---

### 3. Google Dorking

**All dork types:**
```bash
python main.py dork --target example.com --type all
```

**Specific dork type:**
```bash
python main.py dork --target example.com --type sql
```

**Available types:**
- `sql` - SQL injection related
- `xss` - XSS vulnerabilities
- `files` - Sensitive files
- `login` - Login pages
- `config` - Configuration files
- `backup` - Backup files
- `directory` - Directory listings
- `sensitive` - Sensitive information

**With custom settings:**
```bash
python main.py dork --target example.com --type files --max-results 100 --delay 10
```

---

### 4. Vulnerability Scanning

**Quick scan:**
```bash
python main.py vulnscan --url https://example.com --scan-type quick
```

**Full scan:**
```bash
python main.py vulnscan --url https://example.com --scan-type full
```

**Verbose output:**
```bash
python main.py vulnscan --url https://example.com --scan-type full --verbose
```

---

### 5. XSS Detection

**Basic XSS test:**
```bash
python main.py xss --url "https://example.com/search?q=test"
```

**POST method:**
```bash
python main.py xss --url https://example.com/login --method POST --data "username=admin&password=test"
```

**Aggressive testing (level 3):**
```bash
python main.py xss --url "https://example.com/page?id=1" --level 3
```

---

### 6. SQL Injection Detection

**Basic SQL injection test:**
```bash
python main.py sqli --url "https://example.com/page?id=1"
```

**With specific DBMS:**
```bash
python main.py sqli --url "https://example.com/page?id=1" --dbms mysql
```

**POST method:**
```bash
python main.py sqli --url https://example.com/login --method POST --data "username=admin&password=test"
```

**Aggressive testing:**
```bash
python main.py sqli --url "https://example.com/page?id=1" --level 3
```

---

### 7. Password Attacks

**SSH brute force:**
```bash
python main.py password --target ssh://192.168.1.1 --user admin --wordlist passwords.txt
```

**FTP brute force:**
```bash
python main.py password --target ftp://192.168.1.1 --user admin --wordlist passwords.txt
```

**With more threads:**
```bash
python main.py password --target ssh://192.168.1.1 --user root --wordlist rockyou.txt --threads 10
```

---

### 8. Wireless Security

**Scan networks:**
```bash
python main.py wireless --interface wlan0 --scan
```

**Scan and save results:**
```bash
python main.py wireless --interface wlan0 --scan --output wireless.txt
```

**WPA cracking (requires captured handshake):**
```bash
python main.py wireless --interface wlan0 --target AA:BB:CC:DD:EE:FF --wordlist passwords.txt
```

---

## Combined Workflow Example

### Complete security assessment:

```bash
# 1. Subdomain enumeration
python main.py subdomain --target example.com --output subdomains.txt

# 2. Port scan discovered subdomains
python main.py portscan --target example.com --ports 1-10000 --output ports.txt

# 3. Google dorking
python main.py dork --target example.com --type all --output dorks.txt

# 4. Vulnerability scan
python main.py vulnscan --url https://example.com --scan-type full --output vulns.json

# 5. Test for XSS
python main.py xss --url "https://example.com/search?q=test" --level 2 --output xss.json

# 6. Test for SQL injection
python main.py sqli --url "https://example.com/page?id=1" --level 2 --output sqli.json
```

---

## Tips & Best Practices

### 1. Legal & Ethical
- ⚠️ **ALWAYS get written permission** before testing
- Only test systems you own or have authorization for
- Review the legal disclaimer: `python main.py disclaimer`

### 2. Performance
- Adjust threads based on your network and target capacity
- Use appropriate timeouts to avoid false positives
- Increase delays for Google dorking to avoid rate limiting

### 3. Output Management
- All results are saved in the `output/` directory by default
- Use descriptive output filenames for better organization
- JSON format is recommended for further processing

### 4. Wordlists
- Create custom wordlists for specific targets
- Use larger wordlists for comprehensive testing
- Common wordlists location: `data/wordlists/`

### 5. Scanning Efficiency
- Start with quick scans to identify targets
- Use full scans on confirmed targets
- Combine multiple modules for comprehensive testing

---

## Troubleshooting

### Permission Denied (Linux)
```bash
# Port scanning might require root
sudo python main.py portscan --target example.com

# Wireless scanning requires root
sudo python main.py wireless --interface wlan0 --scan
```

### Module Not Found
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Timeout Errors
```bash
# Increase timeout values
python main.py portscan --target example.com --timeout 5
```

### Rate Limiting
```bash
# Increase delays between requests
python main.py dork --target example.com --delay 10
```

---

## Configuration

Edit `config.yaml` to customize default settings:

```yaml
general:
  timeout: 10
  threads: 10
  
subdomain:
  threads: 10
  
port_scanner:
  threads: 50
  timeout: 1
```

---

## Advanced Usage

### Using Config File
```bash
# Edit config.yaml first
python main.py subdomain --target example.com
```

### Verbose Logging
```bash
python main.py subdomain --target example.com --verbose
```

### Custom User Agent
Edit `config.yaml` or `src/core/config.py`

---

## Support & Contributing

- Report issues on GitHub
- Submit pull requests for improvements
- Follow ethical hacking guidelines
- Respect the law and terms of service

---

## Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PTES Standard](http://www.pentest-standard.org/)
- [Bug Bounty Platforms](https://bugbountyplatforms.com/)

---

**Remember: With great power comes great responsibility. Use ethically!** 🔒
