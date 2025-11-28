# Project Structure

```
pentest-toolkit/
│
├── 📄 Configuration Files
│   ├── .env                      # API keys (gitignored, create from .env.example)
│   ├── .env.example             # Template for environment variables
│   ├── .gitignore               # Git ignore rules
│   ├── config.yaml              # Configuration (gitignored, create from example)
│   ├── config.example.yaml      # Safe configuration template
│   └── requirements.txt         # Python dependencies
│
├── 🐍 Main Application
│   ├── main.py                  # CLI entry point
│   ├── api_server.py            # Custom reconnaissance API server
│   ├── setup.py                 # Setup script
│   └── verify_security.py       # Security verification tool
│
├── 🔧 Shell Scripts
│   ├── pentest.bat              # Windows batch launcher
│   ├── pentest.ps1              # PowerShell launcher
│   └── pentest.sh               # Linux/Mac bash launcher
│
├── 📚 Documentation
│   ├── README.md                # Main documentation
│   ├── SECURITY_REPORT.md       # Security audit report
│   ├── INSTALLATION.md          # Installation guide
│   ├── QUICKSTART.md            # Quick start tutorial
│   ├── COMMANDS.md              # Command reference
│   ├── NMAP_INTEGRATION.md      # Nmap integration guide
│   ├── NMAP_QUICKREF.md         # Nmap quick reference
│   └── LICENSE                  # MIT License
│
├── 📁 src/
│   ├── __init__.py
│   │
│   ├── core/                    # Core functionality
│   │   ├── __init__.py
│   │   ├── config.py           # Configuration management (env var support)
│   │   └── utils.py            # Utilities (input validation, sanitization)
│   │
│   └── modules/                # Feature modules
│       ├── __init__.py
│       │
│       ├── reconnaissance/      # 🔍 Reconnaissance tools
│       │   ├── __init__.py
│       │   ├── censys_recon.py        # Censys Search API
│       │   ├── custom_api_recon.py    # Custom API client
│       │   ├── dnsdumpster_recon.py   # DNSDumpster scraper
│       │   ├── fofa_recon.py          # FOFA search engine
│       │   ├── free_recon.py          # Free DNS/WHOIS/Headers
│       │   ├── port_scanner.py        # Nmap port scanner
│       │   ├── shodan_recon.py        # Shodan API
│       │   ├── subdomain_enum.py      # Subdomain enumeration
│       │   └── urlscan_recon.py       # URLScan.io API
│       │
│       ├── webapp/              # 🌐 Web application testing
│       │   ├── __init__.py
│       │   ├── sqli_detector.py       # SQL injection detection
│       │   ├── vulnerability_scanner.py
│       │   └── xss_detector.py        # XSS detection
│       │
│       └── network/             # 🔌 Network tools
│           ├── __init__.py
│           ├── password_attack.py     # Credential attacks
│           └── wireless.py            # WiFi security testing
│
├── 📊 data/
│   └── wordlists/              # Wordlists for enumeration
│       └── subdomains.txt      # Subdomain wordlist
│
└── 📤 output/
    ├── archive/                # Old scan results (archived)
    └── (scan results)          # Fresh reconnaissance results

```

## Key Directories

### `/src/core/`
Core functionality shared across modules:
- **config.py** - Loads configuration from config.yaml and environment variables
- **utils.py** - Input validation, sanitization, and helper functions

### `/src/modules/reconnaissance/`
Reconnaissance and OSINT modules:
- **free_recon.py** - No API required (DNS, WHOIS, HTTP headers)
- **shodan_recon.py** - Shodan API integration
- **urlscan_recon.py** - URLScan.io website analysis
- **censys_recon.py** - Censys certificate/host search
- **fofa_recon.py** - FOFA cyberspace search
- **port_scanner.py** - Nmap-powered port scanning
- **subdomain_enum.py** - Multi-source subdomain discovery

### `/src/modules/webapp/`
Web application vulnerability testing:
- **vulnerability_scanner.py** - General web vulnerability scanner
- **xss_detector.py** - Cross-site scripting detection
- **sqli_detector.py** - SQL injection detection

### `/src/modules/network/`
Network security testing:
- **password_attack.py** - Brute force and dictionary attacks
- **wireless.py** - WiFi security testing

## Important Files

### Security Files (Gitignored)
- `.env` - Contains all API keys and secrets
- `config.yaml` - Configuration with sensitive settings

### Templates (Safe to Commit)
- `.env.example` - Template for environment variables
- `config.example.yaml` - Safe configuration template

### Documentation
- `README.md` - Complete usage guide
- `SECURITY_REPORT.md` - Detailed security audit
- `INSTALLATION.md` - Step-by-step installation
- `COMMANDS.md` - Command reference

## Security Notes

🔒 **Gitignored Files:**
- `.env` - API keys and secrets
- `config.yaml` - Configuration with keys
- `output/*.json` - Scan results may contain sensitive data
- `__pycache__/` - Python cache
- `*.log` - Log files may contain sensitive data

✅ **Safe to Commit:**
- `.env.example` - Template only
- `config.example.yaml` - No real credentials
- `src/**/*.py` - Source code
- Documentation files
- `requirements.txt`

## Quick Navigation

```bash
# View main code
cd src/modules/reconnaissance

# View documentation
ls *.md

# Check configuration
cat config.example.yaml

# Verify security
python verify_security.py
```

## Module Count
- **Reconnaissance:** 9 modules
- **Web Testing:** 3 modules
- **Network:** 2 modules
- **Total:** 14+ security testing modules
