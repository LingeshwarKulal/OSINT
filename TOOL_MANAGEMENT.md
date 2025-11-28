# Tool Management System

## Overview
The API now includes a comprehensive tool management system that provides visibility into all available features, both implemented and ready to implement.

## Statistics
- **Total Categories**: 9
- **Total Tools**: 34
- **Active Tools**: 19 (ready to use)
- **Available Tools**: 15 (ready for implementation)
- **Coverage**: 55.9% implemented

## Tool Management Endpoints

### 1. List All Tools
**GET** `/tools/list`

Returns comprehensive information about all tools including:
- Tool name and endpoint
- Description
- Parameters
- Features
- Status (active/available)
- Implementation notes

**Response includes:**
- `total_categories`: Number of tool categories
- `total_tools`: Total number of tools
- `active_tools`: Number of implemented tools
- `available_tools`: Number of tools ready to implement
- `tools`: Detailed tool information
- `api_info`: API version and authentication details
- `statistics`: Implementation statistics

### 2. Get Categories
**GET** `/tools/categories`

Returns a list of all tool categories with descriptions:
- Reconnaissance
- Web Analysis
- Content Extraction
- Geolocation
- Security Testing
- Breach Intelligence
- Historical Data
- Comprehensive Scans
- Scan Management

### 3. Get Examples
**GET** `/tools/examples`

Returns example requests for each tool category.

## Tool Categories

### 🔍 Reconnaissance (8 tools)
**Active (5):**
- DNS lookup - `/dns/{domain}`
- WHOIS information - `/whois/{domain}`
- Subdomain enumeration - `/subdomains/{domain}` (4 methods)
- Reverse DNS - `/reverse-dns/{ip}`
- WHOIS history - `/whois-history/{domain}`

**Available (3):**
- Port scanner - `/ports/{target}` (Module exists)
- Shodan lookup - `/shodan/host/{ip}` (Module exists)
- Passive DNS - `/passive-dns/{domain}` (Ready to implement)

### 🌐 Web Analysis (8 tools)
**Active (6):**
- HTTP headers - `/headers?url={url}`
- SSL certificate - `/ssl/{domain}`
- Security headers - `/security-headers?url={url}`
- Technology detection - `/technologies?url={url}`
- Web crawler - `/crawl/{target}` (depth control, page limits)
- API discovery - `/api-discover/{domain}` (REST, GraphQL, Swagger)

**Available (2):**
- Vulnerability scanner - `/vulnscan?url={url}` (Module exists)
- WAF detection - `/waf-detect/{url}` (Ready to implement)

### 📄 Content Extraction (6 tools)
**Active (4):**
- Email harvesting - `/emails?url={url}`
- Link extraction - `/links?url={url}`
- Metadata extraction - `/metadata?url={url}`
- Robots.txt & sitemap - `/robots/{domain}`

**Available (2):**
- Git exposure scanner - `/git-scan/{url}` (Ready to implement)
- JavaScript analysis - `/js-analysis/{url}` (Ready to implement)

### 🌍 Geolocation (2 tools)
**Active (1):**
- IP geolocation - `/geolocation/{ip}`

**Available (1):**
- Traceroute - `/traceroute/{target}` (Ready to implement)

### 🔐 Security Testing (3 tools)
**Available (3):**
- SQL injection detection - `/sqli-test/{url}` (Module exists)
- XSS detection - `/xss-test/{url}` (Module exists)
- CORS testing - `/cors-test/{url}` (Ready to implement)

### 💥 Breach Intelligence (3 tools)
**Available (3):**
- Breach check - `/breach-check/{identifier}` (Ready to implement)
- Username enumeration - `/username-check/{username}` (Ready to implement)
- Paste monitoring - `/paste-monitor/{keyword}` (Ready to implement)

### 📚 Historical Data (1 tool)
**Available (1):**
- Wayback Machine - `/wayback/{url}` (Ready to implement)

### 🎯 Comprehensive Scans (1 tool)
**Active (1):**
- Full scan - `/comprehensive/{target}` (all modules)

### 📊 Scan Management (2 tools)
**Active (2):**
- List scans - `/scans?limit={n}`
- Search scans - `/search?query={keyword}`

## Usage Examples

### Get All Tools
```bash
curl -X GET "http://127.0.0.1:8000/tools/list" \
  -H "X-API-Key: your-api-key"
```

### Get Tool Categories
```bash
curl -X GET "http://127.0.0.1:8000/tools/categories" \
  -H "X-API-Key: your-api-key"
```

### Get Tool Examples
```bash
curl -X GET "http://127.0.0.1:8000/tools/examples" \
  -H "X-API-Key: your-api-key"
```

## Testing

Run comprehensive test:
```bash
python test_comprehensive_tools.py
```

Run tool management tests:
```bash
python test_tool_management.py
```

## Next Steps

Based on the tool management system, you can prioritize which "available" features to implement:

**High Priority (modules already exist):**
1. Port scanner endpoint (`/ports/{target}`)
2. Shodan integration endpoint (`/shodan/host/{ip}`)
3. Vulnerability scanner endpoint (`/vulnscan`)
4. SQL injection testing endpoint (`/sqli-test/{url}`)
5. XSS testing endpoint (`/xss-test/{url}`)

**Medium Priority (easy to implement):**
1. WAF detection
2. Git exposure scanner
3. JavaScript analysis
4. CORS testing
5. Traceroute

**Future Enhancements:**
1. Breach intelligence (HIBP API integration)
2. Username enumeration (Sherlock-style)
3. Paste monitoring
4. Wayback Machine integration
5. Passive DNS

## API Information
- **Version**: 2.0.0
- **Authentication**: X-API-Key header required
- **Base URL**: http://127.0.0.1:8000
- **Documentation**: http://127.0.0.1:8000/docs
- **Health Check**: http://127.0.0.1:8000/health
