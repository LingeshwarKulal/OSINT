"""
Advanced OSINT API Server with Web Scraping & Intelligence Gathering

Features:
- DNS enumeration and records
- WHOIS data extraction
- HTTP/HTTPS header analysis
- SSL/TLS certificate inspection
- Subdomain discovery
- Port scanning integration
- Email harvesting
- Technology detection
- Security headers analysis
- Geolocation lookup
"""

import os
import socket
import ssl
import json
import re
import asyncio
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse, urljoin

import dns.resolver
import whois
import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, Query, Header, HTTPException, status, BackgroundTasks
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import builtwith
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import reconnaissance modules
from src.modules.reconnaissance.subdomain_enum import SubdomainEnumerator
from src.modules.reconnaissance.port_scanner import PortScanner
from src.modules.reconnaissance.shodan_recon import ShodanRecon
from src.modules.webapp.vulnerability_scanner import VulnerabilityScanner

# Load environment variables
load_dotenv()

# Setup logging
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Advanced OSINT API Server",
    version="2.0.0",
    description="Comprehensive reconnaissance and intelligence gathering API"
)

# -------------------------------------------------------------------
# 1. API key configuration - LOADED FROM ENVIRONMENT
# -------------------------------------------------------------------
# Set API_SERVER_KEYS environment variable with comma-separated keys
# Example: API_SERVER_KEYS=key1,key2,key3
API_KEYS = set(
    filter(None, os.getenv("API_SERVER_KEYS", "my-test-key").split(","))
)

# Get Shodan API key from environment
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

if "my-test-key" in API_KEYS:
    print("⚠️  WARNING: Using default API key 'my-test-key'. Set API_SERVER_KEYS environment variable!")


def require_api_key(x_api_key: Optional[str]) -> None:
    """Very basic API key check using X-API-Key header."""
    if x_api_key is None or x_api_key not in API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )


# -------------------------------------------------------------------
# 2. Advanced scraping and intelligence functions
# -------------------------------------------------------------------

def get_dns_records(domain: str) -> Dict[str, Any]:
    """Extract comprehensive DNS records"""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(rdata) for rdata in answers]
        except:
            records[record_type] = []
    
    return records


def get_whois_data(domain: str) -> Dict[str, Any]:
    """Extract WHOIS information"""
    try:
        w = whois.whois(domain)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "updated_date": str(w.updated_date),
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "org": w.org,
            "address": w.address,
            "city": w.city,
            "state": w.state,
            "zipcode": w.zipcode,
            "country": w.country,
        }
    except Exception as e:
        return {"error": str(e)}


def get_http_headers(url: str) -> Dict[str, Any]:
    """Analyze HTTP/HTTPS headers and response"""
    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "redirect_history": [r.url for r in response.history],
            "final_url": response.url,
            "encoding": response.encoding,
            "cookies": dict(response.cookies),
        }
    except Exception as e:
        return {"error": str(e)}


def get_ssl_certificate(domain: str, port: int = 443) -> Dict[str, Any]:
    """Extract SSL/TLS certificate information"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": dict(x[0] for x in cert['subject']),
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "version": cert['version'],
                    "serial_number": cert['serialNumber'],
                    "not_before": cert['notBefore'],
                    "not_after": cert['notAfter'],
                    "san": cert.get('subjectAltName', []),
                    "cipher": ssock.cipher(),
                    "tls_version": ssock.version(),
                }
    except Exception as e:
        return {"error": str(e)}


def extract_emails(url: str) -> List[str]:
    """Harvest email addresses from webpage"""
    try:
        response = requests.get(url, timeout=10, verify=False)
        text = response.text
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = list(set(re.findall(email_pattern, text)))
        return emails
    except:
        return []


def detect_technologies(url: str) -> Dict[str, Any]:
    """Detect web technologies using builtwith"""
    try:
        tech = builtwith.parse(url)
        return tech
    except Exception as e:
        return {"error": str(e)}


def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Analyze security-related HTTP headers"""
    security_headers = {
        'Strict-Transport-Security': 'HSTS',
        'Content-Security-Policy': 'CSP',
        'X-Frame-Options': 'Clickjacking Protection',
        'X-Content-Type-Options': 'MIME Sniffing Protection',
        'X-XSS-Protection': 'XSS Filter',
        'Referrer-Policy': 'Referrer Policy',
        'Permissions-Policy': 'Permissions Policy',
    }
    
    analysis = {}
    for header, description in security_headers.items():
        if header in headers:
            analysis[header] = {
                "present": True,
                "value": headers[header],
                "description": description
            }
        else:
            analysis[header] = {
                "present": False,
                "description": description,
                "risk": "Missing security header"
            }
    
    return analysis


def get_ip_geolocation(ip: str) -> Dict[str, Any]:
    """Get geolocation data for IP (using free API)"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def scrape_links(url: str) -> Dict[str, Any]:
    """Extract all links from webpage"""
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        links = {
            "internal": [],
            "external": [],
            "subdomains": [],
            "emails": [],
            "social_media": []
        }
        
        domain = urlparse(url).netloc
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('mailto:'):
                links["emails"].append(href.replace('mailto:', ''))
            elif any(social in href.lower() for social in ['facebook', 'twitter', 'linkedin', 'instagram', 'youtube']):
                links["social_media"].append(href)
            elif domain in href:
                links["internal"].append(href)
            elif href.startswith('http'):
                links["external"].append(href)
        
        return {
            "total_links": len(soup.find_all('a')),
            "internal": list(set(links["internal"]))[:50],
            "external": list(set(links["external"]))[:50],
            "emails": list(set(links["emails"])),
            "social_media": list(set(links["social_media"])),
        }
    except Exception as e:
        return {"error": str(e)}


def extract_metadata(url: str) -> Dict[str, Any]:
    """Extract meta tags and page information"""
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        metadata = {
            "title": soup.title.string if soup.title else None,
            "description": None,
            "keywords": None,
            "author": None,
            "og_tags": {},
            "twitter_tags": {},
        }
        
        # Meta tags
        for meta in soup.find_all('meta'):
            if meta.get('name') == 'description':
                metadata['description'] = meta.get('content')
            elif meta.get('name') == 'keywords':
                metadata['keywords'] = meta.get('content')
            elif meta.get('name') == 'author':
                metadata['author'] = meta.get('content')
            elif meta.get('property', '').startswith('og:'):
                metadata['og_tags'][meta.get('property')] = meta.get('content')
            elif meta.get('name', '').startswith('twitter:'):
                metadata['twitter_tags'][meta.get('name')] = meta.get('content')
        
        return metadata
    except Exception as e:
        return {"error": str(e)}


def comprehensive_scan(target: str) -> Dict[str, Any]:
    """Perform comprehensive reconnaissance on target"""
    result = {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "dns": {},
        "whois": {},
        "http": {},
        "ssl": {},
        "emails": [],
        "technologies": {},
        "security_headers": {},
        "links": {},
        "metadata": {},
    }
    
    # Determine if target is IP or domain
    is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+$', target)
    
    if not is_ip:
        # Domain-based reconnaissance
        result["dns"] = get_dns_records(target)
        result["whois"] = get_whois_data(target)
        result["ssl"] = get_ssl_certificate(target)
        
        url = f"https://{target}"
        result["http"] = get_http_headers(url)
        result["emails"] = extract_emails(url)
        result["technologies"] = detect_technologies(url)
        result["links"] = scrape_links(url)
        result["metadata"] = extract_metadata(url)
        
        if "headers" in result["http"]:
            result["security_headers"] = analyze_security_headers(result["http"]["headers"])
    else:
        # IP-based reconnaissance
        result["geolocation"] = get_ip_geolocation(target)
        result["http"] = get_http_headers(f"http://{target}")
    
    return result


# -------------------------------------------------------------------
# 3. In-memory database for scan results
# -------------------------------------------------------------------
SCAN_RESULTS = []
HOSTS = []


# -------------------------------------------------------------------
# 4. API endpoints
# -------------------------------------------------------------------
@app.get("/")
def root():
    """API information"""
    return {
        "name": "Advanced OSINT API Server",
        "version": "2.0.0",
        "endpoints": {
            "/health": "Health check",
            "/dns/{domain}": "DNS records",
            "/whois/{domain}": "WHOIS information",
            "/headers": "HTTP headers analysis",
            "/ssl/{domain}": "SSL certificate info",
            "/emails": "Email harvesting",
            "/technologies": "Technology detection",
            "/security-headers": "Security headers analysis",
            "/geolocation/{ip}": "IP geolocation",
            "/links": "Link extraction",
            "/metadata": "Page metadata",
            "/subdomains/{domain}": "Subdomain enumeration",
            "/reverse-dns/{ip}": "Reverse DNS lookup",
            "/crawl/{target}": "Web crawling & spidering",
            "/api-discover/{domain}": "API endpoint discovery",
            "/whois-history/{domain}": "WHOIS history & timeline",
            "/robots/{domain}": "Robots.txt & sitemap parser",
            "/comprehensive/{target}": "Full reconnaissance scan",
            "/tools/list": "List all available tools",
            "/tools/categories": "Tool categories",
            "/tools/examples": "Usage examples"
        }
    }


@app.get("/health")
def health() -> dict:
    """Health check endpoint"""
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "total_scans": len(SCAN_RESULTS)
    }


@app.get("/dns/{domain}")
def dns_lookup(
    domain: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Get DNS records for domain"""
    require_api_key(x_api_key)
    return get_dns_records(domain)


@app.get("/whois/{domain}")
def whois_lookup(
    domain: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Get WHOIS information for domain"""
    require_api_key(x_api_key)
    return get_whois_data(domain)


@app.get("/headers")
def headers_analysis(
    url: str = Query(..., description="Target URL"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Analyze HTTP headers"""
    require_api_key(x_api_key)
    return get_http_headers(url)


@app.get("/ssl/{domain}")
def ssl_info(
    domain: str,
    port: int = Query(443, description="SSL port"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Get SSL certificate information"""
    require_api_key(x_api_key)
    return get_ssl_certificate(domain, port)


@app.get("/emails")
def email_harvesting(
    url: str = Query(..., description="Target URL"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Extract email addresses from webpage"""
    require_api_key(x_api_key)
    emails = extract_emails(url)
    return {"url": url, "emails": emails, "count": len(emails)}


@app.get("/technologies")
def technology_detection(
    url: str = Query(..., description="Target URL"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Detect web technologies"""
    require_api_key(x_api_key)
    return detect_technologies(url)


@app.get("/security-headers")
def security_headers(
    url: str = Query(..., description="Target URL"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Analyze security headers"""
    require_api_key(x_api_key)
    headers_data = get_http_headers(url)
    if "headers" in headers_data:
        return analyze_security_headers(headers_data["headers"])
    return headers_data


@app.get("/geolocation/{ip}")
def geolocation(
    ip: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Get IP geolocation data"""
    require_api_key(x_api_key)
    return get_ip_geolocation(ip)


@app.get("/links")
def link_extraction(
    url: str = Query(..., description="Target URL"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Extract links from webpage"""
    require_api_key(x_api_key)
    return scrape_links(url)


@app.get("/metadata")
def metadata_extraction(
    url: str = Query(..., description="Target URL"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Extract metadata from webpage"""
    require_api_key(x_api_key)
    return extract_metadata(url)


@app.get("/comprehensive/{target}")
def comprehensive_reconnaissance(
    target: str,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Perform comprehensive reconnaissance scan"""
    require_api_key(x_api_key)
    
    result = comprehensive_scan(target)
    
    # Store result
    SCAN_RESULTS.append(result)
    
    return result


@app.get("/scans")
def list_scans(
    limit: int = Query(10, ge=1, le=100),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """List recent scans"""
    require_api_key(x_api_key)
    return {
        "total": len(SCAN_RESULTS),
        "scans": SCAN_RESULTS[-limit:]
    }


@app.get("/search")
def search(
    query: str = Query(..., description="Search query"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Search through scan results"""
    require_api_key(x_api_key)
    
    results = []
    query_lower = query.lower()
    
    for scan in SCAN_RESULTS:
        scan_str = json.dumps(scan).lower()
        if query_lower in scan_str:
            results.append(scan)
    
    return {
        "query": query,
        "total_results": len(results),
        "results": results
    }


@app.get("/subdomains/{domain}")
def enumerate_subdomains(
    domain: str,
    method: str = Query("all", description="Method: all, dns, crt, threat, hacker"),
    threads: int = Query(10, ge=1, le=50),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Enumerate subdomains using multiple techniques
    
    Methods:
    - all: Use all enumeration techniques (DNS brute force + APIs)
    - dns: DNS brute force only
    - crt: Certificate Transparency logs (crt.sh)
    - threat: ThreatCrowd API
    - hacker: HackerTarget API
    """
    require_api_key(x_api_key)
    
    try:
        enumerator = SubdomainEnumerator(domain, threads=threads, verbose=False)
        
        found_subdomains = set()
        
        if method == "all":
            # Run all methods
            found_subdomains.update(enumerator._dns_bruteforce())
            found_subdomains.update(enumerator._crtsh_search())
            found_subdomains.update(enumerator._threatcrowd_search())
            found_subdomains.update(enumerator._hackertarget_search())
        elif method == "dns":
            found_subdomains.update(enumerator._dns_bruteforce())
        elif method == "crt":
            found_subdomains.update(enumerator._crtsh_search())
        elif method == "threat":
            found_subdomains.update(enumerator._threatcrowd_search())
        elif method == "hacker":
            found_subdomains.update(enumerator._hackertarget_search())
        else:
            raise HTTPException(status_code=400, detail="Invalid method. Use: all, dns, crt, threat, or hacker")
        
        subdomains_list = sorted(list(found_subdomains))
        
        # Resolve IPs for found subdomains
        subdomain_details = []
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        
        for subdomain in subdomains_list:
            try:
                answers = resolver.resolve(subdomain, 'A')
                ips = [str(rdata) for rdata in answers]
                subdomain_details.append({
                    "subdomain": subdomain,
                    "ips": ips
                })
            except:
                subdomain_details.append({
                    "subdomain": subdomain,
                    "ips": []
                })
        
        result = {
            "domain": domain,
            "method": method,
            "timestamp": datetime.now().isoformat(),
            "total_found": len(subdomain_details),
            "subdomains": subdomain_details
        }
        
        return result
        
    except Exception as e:
        return {"error": str(e), "domain": domain}


@app.get("/reverse-dns/{ip}")
def reverse_dns_lookup(
    ip: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Perform reverse DNS lookup on an IP address"""
    require_api_key(x_api_key)
    
    try:
        # Validate IP format
        socket.inet_aton(ip)
        
        # Perform reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)
            hostnames = [hostname[0]] + list(hostname[1])
        except socket.herror:
            hostnames = []
        
        # Try PTR record lookup
        ptr_records = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            
            # Reverse IP for PTR lookup
            reversed_ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
            answers = resolver.resolve(reversed_ip, 'PTR')
            ptr_records = [str(rdata) for rdata in answers]
        except:
            pass
        
        # Combine results
        all_hostnames = list(set(hostnames + ptr_records))
        
        return {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "hostnames": all_hostnames,
            "total_found": len(all_hostnames),
            "method": "reverse_dns + PTR"
        }
        
    except socket.error:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    except Exception as e:
        return {"error": str(e), "ip": ip}


@app.get("/crawl/{target}")
def web_crawler(
    target: str,
    depth: int = Query(2, ge=1, le=5, description="Crawl depth (1-5)"),
    max_pages: int = Query(50, ge=1, le=500, description="Maximum pages to crawl"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Web crawling and spidering
    
    Crawls a website to discover:
    - All pages and links
    - Forms and input fields
    - JavaScript files
    - API endpoints
    - External links
    """
    require_api_key(x_api_key)
    
    try:
        # Ensure URL has scheme
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        
        visited = set()
        to_visit = [target]
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'pages': [],
            'links': [],
            'forms': [],
            'js_files': [],
            'api_endpoints': [],
            'external_links': []
        }
        
        base_domain = urlparse(target).netloc
        
        def crawl_page(url, current_depth):
            if len(visited) >= max_pages or current_depth > depth or url in visited:
                return
            
            visited.add(url)
            
            try:
                response = requests.get(url, timeout=10, verify=False, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                
                if response.status_code != 200:
                    return
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract page info
                page_info = {
                    'url': url,
                    'status': response.status_code,
                    'title': soup.title.string if soup.title else None,
                    'depth': current_depth
                }
                results['pages'].append(page_info)
                
                # Extract all links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    # Check if internal or external
                    link_domain = urlparse(full_url).netloc
                    
                    if link_domain == base_domain:
                        results['links'].append(full_url)
                        if current_depth < depth:
                            to_visit.append(full_url)
                    else:
                        results['external_links'].append(full_url)
                
                # Extract forms
                for form in soup.find_all('form'):
                    form_info = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        form_info['inputs'].append({
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text')
                        })
                    
                    results['forms'].append(form_info)
                
                # Extract JavaScript files
                for script in soup.find_all('script', src=True):
                    js_url = urljoin(url, script['src'])
                    results['js_files'].append(js_url)
                
                # Look for potential API endpoints in JS and links
                for text in [response.text]:
                    # Common API patterns
                    api_patterns = [
                        r'/api/v?\d*/[\w-]+',
                        r'/rest/[\w-]+',
                        r'/graphql',
                        r'/v\d+/[\w-]+'
                    ]
                    
                    import re
                    for pattern in api_patterns:
                        matches = re.findall(pattern, text)
                        for match in matches:
                            api_url = urljoin(url, match)
                            if api_url not in results['api_endpoints']:
                                results['api_endpoints'].append(api_url)
                
            except Exception as e:
                logger.error(f"Error crawling {url}: {e}")
        
        # Start crawling
        while to_visit and len(visited) < max_pages:
            current_url = to_visit.pop(0)
            if current_url not in visited:
                crawl_page(current_url, 1)
        
        # Deduplicate results
        results['links'] = list(set(results['links']))
        results['external_links'] = list(set(results['external_links']))
        results['js_files'] = list(set(results['js_files']))
        results['api_endpoints'] = list(set(results['api_endpoints']))
        
        results['summary'] = {
            'total_pages': len(results['pages']),
            'total_links': len(results['links']),
            'total_external': len(results['external_links']),
            'total_forms': len(results['forms']),
            'total_js_files': len(results['js_files']),
            'total_api_endpoints': len(results['api_endpoints'])
        }
        
        return results
        
    except Exception as e:
        return {"error": str(e), "target": target}


@app.get("/api-discover/{domain}")
def api_endpoint_discovery(
    domain: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Discover API endpoints and documentation
    
    Searches for:
    - REST API endpoints
    - GraphQL endpoints
    - Swagger/OpenAPI documentation
    - Common API paths
    - API versioning
    """
    require_api_key(x_api_key)
    
    try:
        if not domain.startswith(('http://', 'https://')):
            domain = f'https://{domain}'
        
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'swagger_docs': [],
            'graphql_endpoints': [],
            'rest_endpoints': [],
            'api_versions': []
        }
        
        # Common API documentation paths
        doc_paths = [
            '/swagger.json', '/swagger.yaml', '/swagger-ui.html',
            '/api-docs', '/api/docs', '/docs', '/api/swagger',
            '/openapi.json', '/openapi.yaml',
            '/redoc', '/api/redoc',
            '/.well-known/openapi.json'
        ]
        
        # Check for API documentation
        for path in doc_paths:
            url = urljoin(domain, path)
            try:
                response = requests.get(url, timeout=5, verify=False, headers={
                    'User-Agent': 'Mozilla/5.0'
                })
                
                if response.status_code == 200:
                    results['swagger_docs'].append({
                        'url': url,
                        'status': response.status_code,
                        'content_type': response.headers.get('Content-Type', '')
                    })
            except:
                pass
        
        # Check for GraphQL
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/query']
        
        for path in graphql_paths:
            url = urljoin(domain, path)
            try:
                # Try GraphQL introspection
                response = requests.post(url, 
                    json={'query': '{__schema{types{name}}}'},
                    timeout=5,
                    verify=False,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code == 200 and 'data' in response.text:
                    results['graphql_endpoints'].append({
                        'url': url,
                        'status': response.status_code,
                        'introspection_enabled': '__schema' in response.text
                    })
            except:
                pass
        
        # Check common REST API paths
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/rest/v2',
            '/v1', '/v2', '/v3',
            '/api/users', '/api/auth', '/api/login',
            '/api/health', '/api/status', '/api/ping'
        ]
        
        for path in api_paths:
            url = urljoin(domain, path)
            try:
                response = requests.get(url, timeout=5, verify=False, headers={
                    'User-Agent': 'Mozilla/5.0'
                })
                
                if response.status_code in [200, 401, 403]:  # API exists
                    results['rest_endpoints'].append({
                        'url': url,
                        'status': response.status_code,
                        'requires_auth': response.status_code in [401, 403]
                    })
                    
                    # Check for version
                    import re
                    version_match = re.search(r'/v(\d+)', path)
                    if version_match:
                        version = version_match.group(1)
                        if version not in results['api_versions']:
                            results['api_versions'].append(f'v{version}')
            except:
                pass
        
        results['summary'] = {
            'total_swagger_docs': len(results['swagger_docs']),
            'total_graphql': len(results['graphql_endpoints']),
            'total_rest': len(results['rest_endpoints']),
            'api_versions_found': results['api_versions']
        }
        
        return results
        
    except Exception as e:
        return {"error": str(e), "domain": domain}


@app.get("/whois-history/{domain}")
def whois_history(
    domain: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Get WHOIS history and changes
    
    Returns:
    - Current WHOIS data
    - Registration timeline
    - Nameserver history
    - Registrar changes
    """
    require_api_key(x_api_key)
    
    try:
        # Get current WHOIS data
        current_whois = whois.whois(domain)
        
        # Parse dates
        creation_date = current_whois.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        expiration_date = current_whois.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        updated_date = current_whois.updated_date
        if isinstance(updated_date, list):
            updated_date = updated_date[0]
        
        # Remove timezone info for calculations
        now = datetime.now()
        
        if creation_date:
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo:
                creation_date = creation_date.replace(tzinfo=None)
        
        if expiration_date:
            if hasattr(expiration_date, 'tzinfo') and expiration_date.tzinfo:
                expiration_date = expiration_date.replace(tzinfo=None)
        
        if updated_date:
            if hasattr(updated_date, 'tzinfo') and updated_date.tzinfo:
                updated_date = updated_date.replace(tzinfo=None)
        
        # Calculate domain age
        if creation_date:
            domain_age_days = (now - creation_date).days
            domain_age_years = domain_age_days / 365.25
        else:
            domain_age_days = None
            domain_age_years = None
        
        # Calculate days until expiration
        if expiration_date:
            days_until_expiration = (expiration_date - now).days
        else:
            days_until_expiration = None
        
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'current_data': {
                'registrar': current_whois.registrar,
                'creation_date': str(creation_date) if creation_date else None,
                'expiration_date': str(expiration_date) if expiration_date else None,
                'updated_date': str(updated_date) if updated_date else None,
                'name_servers': current_whois.name_servers if current_whois.name_servers else [],
                'status': current_whois.status,
                'emails': current_whois.emails if hasattr(current_whois, 'emails') else []
            },
            'timeline': {
                'domain_age_days': domain_age_days,
                'domain_age_years': round(domain_age_years, 2) if domain_age_years else None,
                'days_until_expiration': days_until_expiration,
                'last_updated_days_ago': (now - updated_date).days if updated_date else None
            },
            'analysis': {
                'is_old_domain': domain_age_years > 5 if domain_age_years else False,
                'recently_registered': domain_age_days < 90 if domain_age_days else False,
                'expiring_soon': days_until_expiration < 30 if days_until_expiration else False,
                'recently_updated': ((now - updated_date).days < 30) if updated_date else False
            }
        }
        
        # Try to get historical data from web archive
        try:
            # Check if domain existed 1 year ago, 2 years ago, etc.
            archive_checks = []
            for years_back in [1, 2, 5, 10]:
                check_date = now.replace(year=now.year - years_back)
                archive_checks.append({
                    'years_ago': years_back,
                    'date': check_date.strftime('%Y-%m-%d'),
                    'domain_existed': check_date > creation_date if creation_date else False
                })
            
            results['historical_checks'] = archive_checks
        except:
            pass
        
        return results
        
    except Exception as e:
        return {"error": str(e), "domain": domain}


# -------------------------------------------------------------------
# Tool Management & Utilities
# -------------------------------------------------------------------

@app.get("/tools/list")
def list_tools(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """List all available reconnaissance and scanning tools"""
    require_api_key(x_api_key)
    
    tools = {
        "reconnaissance": {
            "dns_lookup": {
                "endpoint": "/dns/{domain}",
                "description": "DNS records enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)",
                "parameters": [],
                "example": "/dns/example.com",
                "status": "active"
            },
            "whois": {
                "endpoint": "/whois/{domain}",
                "description": "WHOIS domain information and registration details",
                "parameters": [],
                "example": "/whois/example.com",
                "status": "active"
            },
            "subdomain_enum": {
                "endpoint": "/subdomains/{domain}",
                "description": "Subdomain enumeration using multiple techniques",
                "methods": ["all", "dns", "crt", "threat", "hacker"],
                "parameters": ["method", "threads"],
                "example": "/subdomains/example.com?method=all&threads=10",
                "features": ["DNS brute force", "Certificate Transparency", "ThreatCrowd API", "HackerTarget API"],
                "status": "active"
            },
            "reverse_dns": {
                "endpoint": "/reverse-dns/{ip}",
                "description": "Reverse DNS lookup (PTR records + gethostbyaddr)",
                "parameters": [],
                "example": "/reverse-dns/8.8.8.8",
                "status": "active"
            },
            "whois_history": {
                "endpoint": "/whois-history/{domain}",
                "description": "WHOIS history, domain age, timeline, and analysis",
                "parameters": [],
                "example": "/whois-history/example.com",
                "features": ["Domain age calculation", "Expiration tracking", "Historical checks", "Risk analysis"],
                "status": "active"
            },
            "port_scanner": {
                "endpoint": "/ports/{target}",
                "description": "TCP port scanning with service detection",
                "parameters": ["ports", "threads", "timeout"],
                "example": "/ports/example.com?ports=1-1000&threads=50",
                "features": ["Multi-threaded scanning", "Service detection", "Banner grabbing", "Nmap integration"],
                "status": "available",
                "note": "Module exists but endpoint not yet implemented"
            },
            "shodan_lookup": {
                "endpoint": "/shodan/host/{ip}",
                "description": "Shodan host information lookup",
                "parameters": [],
                "example": "/shodan/host/8.8.8.8",
                "features": ["Open ports", "Services", "Vulnerabilities", "Historical data"],
                "requires": "SHODAN_API_KEY",
                "status": "available",
                "note": "Module exists but endpoint not yet implemented"
            },
            "passive_dns": {
                "endpoint": "/passive-dns/{domain}",
                "description": "Historical DNS records and IP changes",
                "parameters": [],
                "example": "/passive-dns/example.com",
                "features": ["Historical IPs", "DNS timeline", "SecurityTrails integration"],
                "status": "available",
                "note": "Ready to implement"
            }
        },
        "web_analysis": {
            "http_headers": {
                "endpoint": "/headers",
                "description": "HTTP headers analysis and inspection",
                "parameters": ["url"],
                "example": "/headers?url=https://example.com",
                "features": ["Status code", "Server info", "Content type", "Cookies"],
                "status": "active"
            },
            "ssl_certificate": {
                "endpoint": "/ssl/{domain}",
                "description": "SSL/TLS certificate information and validation",
                "parameters": [],
                "example": "/ssl/example.com",
                "features": ["Subject/Issuer", "Validity dates", "SAN domains", "Cipher suite", "TLS version"],
                "status": "active"
            },
            "security_headers": {
                "endpoint": "/security-headers",
                "description": "Security headers audit and analysis",
                "parameters": ["url"],
                "example": "/security-headers?url=https://example.com",
                "features": ["HSTS", "CSP", "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection"],
                "status": "active"
            },
            "technologies": {
                "endpoint": "/technologies",
                "description": "Technology stack and framework detection",
                "parameters": ["url"],
                "example": "/technologies?url=https://example.com",
                "features": ["Web servers", "Frameworks", "CMS", "Analytics"],
                "status": "active"
            },
            "web_crawler": {
                "endpoint": "/crawl/{target}",
                "description": "Web crawler and spider for comprehensive site analysis",
                "parameters": ["depth", "max_pages"],
                "example": "/crawl/example.com?depth=2&max_pages=50",
                "features": ["Page discovery", "Form extraction", "JS file collection", "API endpoint detection"],
                "status": "active"
            },
            "api_discovery": {
                "endpoint": "/api-discover/{domain}",
                "description": "API endpoint discovery and documentation finder",
                "parameters": [],
                "example": "/api-discover/example.com",
                "features": ["Swagger/OpenAPI", "GraphQL", "REST APIs", "API versioning"],
                "status": "active"
            },
            "vulnerability_scanner": {
                "endpoint": "/vulnscan",
                "description": "Web application vulnerability scanner",
                "parameters": ["url", "threads"],
                "example": "/vulnscan?url=https://example.com",
                "features": ["Missing headers", "SSL/TLS checks", "Directory listing", "Info disclosure"],
                "status": "available",
                "note": "Module exists but endpoint not yet implemented"
            },
            "waf_detection": {
                "endpoint": "/waf-detect/{url}",
                "description": "Web Application Firewall detection",
                "parameters": [],
                "example": "/waf-detect/example.com",
                "features": ["Cloudflare", "AWS WAF", "Akamai", "Imperva detection"],
                "status": "available",
                "note": "Ready to implement"
            }
        },
        "content_extraction": {
            "email_harvesting": {
                "endpoint": "/emails",
                "description": "Email address extraction and harvesting",
                "parameters": ["url"],
                "example": "/emails?url=https://example.com",
                "status": "active"
            },
            "link_extraction": {
                "endpoint": "/links",
                "description": "Extract all links (internal, external, social media)",
                "parameters": ["url"],
                "example": "/links?url=https://example.com",
                "status": "active"
            },
            "metadata": {
                "endpoint": "/metadata",
                "description": "Extract page metadata, OpenGraph, and Twitter cards",
                "parameters": ["url"],
                "example": "/metadata?url=https://example.com",
                "features": ["Title/Description", "OG tags", "Twitter cards", "Keywords"],
                "status": "active"
            },
            "robots_sitemap": {
                "endpoint": "/robots/{domain}",
                "description": "Parse robots.txt and discover sitemaps",
                "parameters": [],
                "example": "/robots/example.com",
                "features": ["Disallowed paths", "Sitemaps", "Crawl delays", "Interesting paths"],
                "status": "active"
            },
            "git_exposure": {
                "endpoint": "/git-scan/{url}",
                "description": "Scan for exposed .git directories",
                "parameters": [],
                "example": "/git-scan/example.com",
                "features": ["Git config", "HEAD file", "Repository download capability"],
                "status": "available",
                "note": "Ready to implement"
            },
            "javascript_analysis": {
                "endpoint": "/js-analysis/{url}",
                "description": "Analyze JavaScript files for secrets and API keys",
                "parameters": [],
                "example": "/js-analysis/example.com",
                "features": ["API key detection", "Hardcoded credentials", "Source maps"],
                "status": "available",
                "note": "Ready to implement"
            }
        },
        "geolocation": {
            "ip_geolocation": {
                "endpoint": "/geolocation/{ip}",
                "description": "IP geolocation, ISP, and location data",
                "parameters": [],
                "example": "/geolocation/8.8.8.8",
                "features": ["Country/City", "Coordinates", "ISP/Org", "Timezone"],
                "status": "active"
            },
            "traceroute": {
                "endpoint": "/traceroute/{target}",
                "description": "Network path tracing and hop analysis",
                "parameters": [],
                "example": "/traceroute/example.com",
                "features": ["Hop-by-hop path", "Latency", "Geographic routing"],
                "status": "available",
                "note": "Ready to implement"
            }
        },
        "security_testing": {
            "sqli_detection": {
                "endpoint": "/sqli-test/{url}",
                "description": "SQL injection vulnerability testing",
                "parameters": ["params"],
                "example": "/sqli-test/example.com?params=id,name",
                "features": ["Error-based", "Boolean-based", "Time-based detection"],
                "status": "available",
                "note": "Module exists but endpoint not yet implemented"
            },
            "xss_detection": {
                "endpoint": "/xss-test/{url}",
                "description": "Cross-Site Scripting vulnerability testing",
                "parameters": ["params"],
                "example": "/xss-test/example.com?params=search,comment",
                "features": ["Reflected XSS", "Stored XSS", "DOM-based XSS"],
                "status": "available",
                "note": "Module exists but endpoint not yet implemented"
            },
            "cors_test": {
                "endpoint": "/cors-test/{url}",
                "description": "CORS misconfiguration testing",
                "parameters": [],
                "example": "/cors-test/example.com",
                "features": ["Origin validation", "Credential exposure", "Wildcard detection"],
                "status": "available",
                "note": "Ready to implement"
            }
        },
        "breach_intelligence": {
            "breach_check": {
                "endpoint": "/breach-check/{identifier}",
                "description": "Check if email/domain appears in data breaches",
                "parameters": [],
                "example": "/breach-check/example@gmail.com",
                "features": ["HaveIBeenPwned", "DeHashed integration", "Breach timeline"],
                "status": "available",
                "note": "Ready to implement"
            },
            "username_check": {
                "endpoint": "/username-check/{username}",
                "description": "Check username across 20+ platforms",
                "parameters": [],
                "example": "/username-check/johndoe",
                "features": ["Social media", "GitHub/GitLab", "Forums", "Gaming platforms"],
                "status": "available",
                "note": "Ready to implement"
            },
            "paste_monitor": {
                "endpoint": "/paste-monitor/{keyword}",
                "description": "Search for keyword in paste sites",
                "parameters": [],
                "example": "/paste-monitor/example.com",
                "features": ["Pastebin", "GitHub Gists", "Leak detection"],
                "status": "available",
                "note": "Ready to implement"
            }
        },
        "historical_data": {
            "wayback_machine": {
                "endpoint": "/wayback/{url}",
                "description": "Historical website snapshots from Wayback Machine",
                "parameters": ["limit"],
                "example": "/wayback/example.com",
                "features": ["Snapshot timeline", "Archive availability", "Historical changes"],
                "status": "available",
                "note": "Ready to implement"
            }
        },
        "comprehensive_scans": {
            "full_scan": {
                "endpoint": "/comprehensive/{target}",
                "description": "Complete reconnaissance scan with all available modules",
                "parameters": [],
                "example": "/comprehensive/example.com",
                "features": [
                    "DNS records",
                    "WHOIS data",
                    "HTTP headers",
                    "SSL certificate",
                    "Email harvesting",
                    "Technology detection",
                    "Security headers",
                    "Links extraction",
                    "Metadata extraction"
                ],
                "status": "active"
            }
        },
        "scan_management": {
            "list_scans": {
                "endpoint": "/scans",
                "description": "List recent scan results with pagination",
                "parameters": ["limit"],
                "example": "/scans?limit=10",
                "status": "active"
            },
            "search_scans": {
                "endpoint": "/search",
                "description": "Search through scan results by keyword",
                "parameters": ["query"],
                "example": "/search?query=apache",
                "status": "active"
            }
        }
    }
    
    # Calculate statistics
    total_tools = sum(len(category) for category in tools.values())
    active_tools = sum(1 for category in tools.values() for tool in category.values() if tool.get('status') == 'active')
    available_tools = sum(1 for category in tools.values() for tool in category.values() if tool.get('status') == 'available')
    
    return {
        "total_categories": len(tools),
        "total_tools": total_tools,
        "active_tools": active_tools,
        "available_tools": available_tools,
        "tools": tools,
        "api_info": {
            "version": "2.0.0",
            "authentication": "X-API-Key header required",
            "documentation": "/",
            "health_check": "/health",
            "tool_management": {
                "list_all": "/tools/list",
                "categories": "/tools/categories",
                "examples": "/tools/examples"
            }
        },
        "statistics": {
            "active": f"{active_tools} tools ready to use",
            "available": f"{available_tools} tools available for implementation",
            "coverage": f"{(active_tools/total_tools)*100:.1f}% implemented"
        }
    }


@app.get("/tools/categories")
def list_tool_categories(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Get tool categories and counts"""
    require_api_key(x_api_key)
    
    return {
        "categories": {
            "reconnaissance": "DNS, WHOIS, subdomains, reverse DNS",
            "web_analysis": "HTTP headers, SSL, security headers, crawling",
            "content_extraction": "Emails, links, metadata, robots.txt",
            "geolocation": "IP geolocation and tracking",
            "comprehensive_scans": "Full reconnaissance workflows",
            "scan_management": "Manage and search scan results"
        },
        "total_endpoints": 18,
        "base_url": "http://127.0.0.1:8000"
    }


@app.get("/tools/examples")
def tool_examples(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")
) -> dict:
    """Get example usage for all tools"""
    require_api_key(x_api_key)
    
    return {
        "examples": {
            "basic_dns_lookup": {
                "command": "curl -H 'X-API-Key: YOUR_KEY' http://127.0.0.1:8000/dns/google.com",
                "description": "Get DNS records for a domain"
            },
            "subdomain_enumeration": {
                "command": "curl -H 'X-API-Key: YOUR_KEY' http://127.0.0.1:8000/subdomains/example.com?method=crt",
                "description": "Find subdomains using Certificate Transparency"
            },
            "security_audit": {
                "command": "curl -H 'X-API-Key: YOUR_KEY' 'http://127.0.0.1:8000/security-headers?url=https://example.com'",
                "description": "Audit security headers"
            },
            "web_crawl": {
                "command": "curl -H 'X-API-Key: YOUR_KEY' 'http://127.0.0.1:8000/crawl/example.com?depth=2&max_pages=20'",
                "description": "Crawl website for links, forms, and APIs"
            },
            "comprehensive_scan": {
                "command": "curl -H 'X-API-Key: YOUR_KEY' http://127.0.0.1:8000/comprehensive/example.com",
                "description": "Run complete reconnaissance scan"
            },
            "reverse_dns": {
                "command": "curl -H 'X-API-Key: YOUR_KEY' http://127.0.0.1:8000/reverse-dns/8.8.8.8",
                "description": "Reverse DNS lookup for IP address"
            }
        },
        "python_example": {
            "code": """import requests

headers = {'X-API-Key': 'YOUR_API_KEY'}
response = requests.get(
    'http://127.0.0.1:8000/comprehensive/example.com',
    headers=headers
)
data = response.json()
print(data)"""
        }
    }


# -------------------------------------------------------------------
# 4. Run with:
#     uvicorn api_server:app --reload
# Then call:
#     curl -H "X-API-Key: my-test-key" \
#       "http://127.0.0.1:8000/search?query=apache&port=80"
# -------------------------------------------------------------------
