# 🔒 Pentest Toolkit - Secure Reconnaissance Framework

A comprehensive penetration testing toolkit with multiple reconnaissance methods and security hardening.

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is designed for legitimate security testing and educational purposes. Users must:
- Obtain written authorization before testing any systems
- Comply with all applicable laws and regulations
- Use responsibly and ethically

Unauthorized access to computer systems is illegal.

## ✨ Features

### Reconnaissance Modules
- **Free Reconnaissance** - DNS, WHOIS, HTTP headers (no API required)
- **Shodan Integration** - IP and host intelligence
- **URLScan.io** - Website analysis and technology detection
- **Censys Integration** - Certificate and host data
- **FOFA Integration** - Cyberspace search engine
- **DNSDumpster** - DNS reconnaissance
- **Custom API Server** - Build your own reconnaissance database

### Additional Tools
- **Port Scanner** - Nmap integration with service detection
- **Subdomain Enumeration** - Multi-source subdomain discovery
- **Vulnerability Scanner** - Web application testing
- **XSS Detection** - Cross-site scripting vulnerability detection
- **SQL Injection Detection** - Database vulnerability testing

## 🔐 Security Features

### Implemented Security Measures
✅ **Environment Variable Support** - API keys loaded from .env (never committed)  
✅ **Input Validation** - Sanitization of user inputs to prevent injection  
✅ **Secure Configuration** - Gitignore protection for sensitive data  
✅ **Port Validation** - Range and format checking  
✅ **Target Validation** - Domain and IP address verification  

### Security Best Practices
- All API keys stored in environment variables
- Comprehensive .gitignore prevents credential exposure
- Input sanitization on all user-provided data
- Subprocess calls use validated parameters only
- No hardcoded credentials in source code

## 📦 Installation

### Prerequisites
- Python 3.8+
- Nmap (for port scanning)
- Windows/Linux/MacOS

### Step 1: Clone Repository
```powershell
git clone https://github.com/yourusername/pentest-toolkit.git
cd pentest-toolkit
```

### Step 2: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
```powershell
# Copy example files
Copy-Item .env.example .env
Copy-Item config.example.yaml config.yaml

# Edit .env with your API keys
notepad .env
```

Add your API keys to `.env`:
```ini
CENSYS_API_KEY=your_censys_key_here
SHODAN_API_KEY=your_shodan_key_here
FOFA_EMAIL=your_email@example.com
FOFA_API_KEY=your_fofa_key_here
URLSCAN_API_KEY=your_urlscan_key_here
API_SERVER_KEYS=your_custom_key1,your_custom_key2
```

### Step 4: Verify Installation
```powershell
python main.py --help
```

## 🚀 Usage

### Basic Reconnaissance
```powershell
# Free reconnaissance (no API required)
python main.py recon -t example.com -m free

# Shodan lookup
python main.py recon -t 8.8.8.8 -m shodan

# URLScan analysis
python main.py recon -t example.com -m urlscan

# Multiple methods
python main.py recon -t example.com -m free
python main.py recon -t example.com -m urlscan
```

### Port Scanning
```powershell
# Scan common ports
python main.py portscan -t example.com

# Custom port range
python main.py portscan -t example.com --ports 1-1000

# Specific ports
python main.py portscan -t example.com --ports 80,443,8080
```

### Subdomain Enumeration
```powershell
# Discover subdomains
python main.py subdomain -d example.com

# Use custom wordlist
python main.py subdomain -d example.com -w custom_wordlist.txt
```

### Custom API Server
```powershell
# Start API server
python api_server.py

# Test API (in another terminal)
curl -H "X-API-Key: your_custom_key" http://localhost:8000/health
```

## 📁 Project Structure

```
pentest-toolkit/
├── main.py                     # Main CLI entry point
├── api_server.py              # Custom reconnaissance API
├── config.yaml                # Configuration (gitignored)
├── .env                       # Environment variables (gitignored)
├── requirements.txt           # Python dependencies
├── SECURITY_REPORT.md        # Security audit and recommendations
│
├── src/
│   ├── core/
│   │   ├── config.py         # Configuration with env var support
│   │   └── utils.py          # Utilities with input validation
│   │
│   └── modules/
│       ├── reconnaissance/
│       │   ├── free_recon.py          # Free DNS/WHOIS
│       │   ├── shodan_recon.py        # Shodan integration
│       │   ├── censys_recon.py        # Censys integration
│       │   ├── fofa_recon.py          # FOFA integration
│       │   ├── urlscan_recon.py       # URLScan.io
│       │   ├── dnsdumpster_recon.py   # DNSDumpster
│       │   ├── subdomain_enum.py      # Subdomain discovery
│       │   ├── port_scanner.py        # Nmap integration
│       │   └── custom_api_recon.py    # Custom API client
│       │
│       ├── webapp/
│       │   ├── vulnerability_scanner.py
│       │   ├── xss_detector.py
│       │   └── sqli_detector.py
│       │
│       └── network/
│           ├── password_attack.py
│           └── wireless.py
│
├── data/
│   └── wordlists/
│       └── subdomains.txt
│
└── output/                    # Scan results (gitignored)
```

## 🔑 API Keys

### Where to Get API Keys

1. **Shodan** - https://account.shodan.io/
   - Free tier: 100 query credits/month
   - Provides IP intelligence and host data

2. **URLScan.io** - https://urlscan.io/user/signup
   - Free tier: 1000 scans/day
   - Website analysis and technology detection

3. **Censys** - https://search.censys.io/account/register
   - Free tier: Limited searches
   - Certificate and host intelligence

4. **FOFA** - https://en.fofa.info/
   - Free tier available
   - Cyberspace search engine

### API Key Security
- **NEVER** commit `.env` or `config.yaml` to git
- Rotate keys regularly
- Use separate keys for testing and production
- Monitor API usage for anomalies

## 🛡️ Security Considerations

### Before Use
1. Review `SECURITY_REPORT.md` for detailed security audit
2. Ensure `.env` is in `.gitignore`
3. Set strong, unique API keys
4. Verify target authorization before scanning

### Secure Defaults
- Config file uses environment variables for sensitive data
- Input validation on all user inputs
- Port ranges validated (1-65535)
- Domain/IP format verification
- No command injection vulnerabilities

### Recommendations
- Use HTTPS for API server in production
- Implement rate limiting
- Enable audit logging
- Encrypt output files containing sensitive data
- Keep dependencies updated

## 📊 Example Output

### Free Reconnaissance
```
DNS Records:
  A: 93.184.216.34
  MX: mail.example.com

WHOIS Info:
  Registrar: Example Registrar
  Creation Date: 1995-08-14

HTTP Headers:
  Server: nginx
  X-Frame-Options: DENY
```

### Port Scan
```
Open Ports:
  22/tcp   - SSH (OpenSSH 8.0)
  80/tcp   - HTTP (nginx 1.18.0)
  443/tcp  - HTTPS (nginx 1.18.0)
```

## 🐛 Troubleshooting

### API Authentication Errors
- Verify API key in `.env` file
- Check key format (no extra spaces)
- Ensure environment variables are loaded

### Command Not Found
- Ensure Python is in PATH
- Activate virtual environment if used
- Check file permissions

### Nmap Not Found
- Install Nmap: https://nmap.org/download.html
- Add Nmap to system PATH
- Restart terminal after installation

## 📚 Documentation

- `SECURITY_REPORT.md` - Comprehensive security audit
- `INSTALLATION.md` - Detailed installation guide
- `QUICKSTART.md` - Quick start tutorial
- `COMMANDS.md` - Complete command reference

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Add tests for new features
4. Ensure security best practices
5. Submit pull request

### Security Contributions
Report security vulnerabilities privately to: security@example.com

## 📄 License

MIT License - See LICENSE file for details

## 🔗 Resources

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Python Security: https://python.readthedocs.io/en/latest/library/security_warnings.html
- Nmap Documentation: https://nmap.org/book/
- Shodan Documentation: https://developer.shodan.io/

## ⚡ Quick Reference

```powershell
# Setup
pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env with your API keys

# Basic Usage
python main.py recon -t example.com -m free      # Free recon
python main.py recon -t 8.8.8.8 -m shodan       # Shodan lookup
python main.py portscan -t example.com          # Port scan
python main.py subdomain -d example.com         # Find subdomains

# API Server
python api_server.py                            # Start server
```

## 📞 Support

- Issues: https://github.com/yourusername/pentest-toolkit/issues
- Documentation: https://github.com/yourusername/pentest-toolkit/wiki
- Security: security@example.com

---

**Remember**: Always obtain authorization before testing any systems. Unauthorized access is illegal.
