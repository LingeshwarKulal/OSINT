"""
Free Reconnaissance Module (No API Keys Required)
Uses public DNS, WHOIS, and other free services
"""

import socket
import dns.resolver
import whois
import requests
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class FreeRecon:
    """Free reconnaissance using public services"""
    
    def __init__(self):
        console.print("[green]✓ Free Recon initialized (no API keys needed)[/green]")
        self.results = {}
    
    def dns_lookup(self, domain: str) -> Dict:
        """Perform DNS lookups"""
        console.print(f"[cyan]🔍 DNS lookup for: {domain}[/cyan]")
        results = {}
        
        try:
            # A records (IPv4)
            a_records = dns.resolver.resolve(domain, 'A')
            results['A'] = [str(r) for r in a_records]
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                results['MX'] = [str(r.exchange) for r in mx_records]
            except:
                results['MX'] = []
            
            # NS records
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                results['NS'] = [str(r) for r in ns_records]
            except:
                results['NS'] = []
            
            # TXT records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                results['TXT'] = [str(r) for r in txt_records]
            except:
                results['TXT'] = []
            
            console.print(f"[green]✓ DNS records found[/green]")
            return results
            
        except Exception as e:
            console.print(f"[red]✗ DNS lookup failed: {e}[/red]")
            return {}
    
    def whois_lookup(self, domain: str) -> Dict:
        """Get WHOIS information"""
        console.print(f"[cyan]📋 WHOIS lookup for: {domain}[/cyan]")
        
        try:
            w = whois.whois(domain)
            console.print(f"[green]✓ WHOIS data retrieved[/green]")
            return {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers
            }
        except Exception as e:
            console.print(f"[yellow]⚠ WHOIS lookup failed: {e}[/yellow]")
            return {}
    
    def http_headers(self, url: str) -> Dict:
        """Get HTTP headers"""
        console.print(f"[cyan]🌐 Getting HTTP headers for: {url}[/cyan]")
        
        try:
            if not url.startswith('http'):
                url = f"https://{url}"
            
            response = requests.head(url, timeout=10, allow_redirects=True)
            console.print(f"[green]✓ Headers retrieved[/green]")
            return dict(response.headers)
            
        except Exception as e:
            console.print(f"[yellow]⚠ HTTP request failed: {e}[/yellow]")
            return {}
    
    def comprehensive_scan(self, domain: str) -> Dict:
        """Perform free comprehensive scan"""
        console.print(Panel.fit(
            f"[bold cyan]Starting Free Reconnaissance[/bold cyan]\n"
            f"Target: [yellow]{domain}[/yellow]\n"
            f"No API keys required!",
            border_style="cyan"
        ))
        
        results = {
            'domain': domain,
            'dns': self.dns_lookup(domain),
            'whois': self.whois_lookup(domain),
            'http_headers': self.http_headers(domain)
        }
        
        self.results = results
        return results
    
    def display_results(self, results: Dict):
        """Display results"""
        console.print("\n[bold green]Reconnaissance Complete![/bold green]\n")
        
        # DNS Results
        if results.get('dns'):
            console.print("[bold cyan]📍 DNS Records:[/bold cyan]")
            for record_type, values in results['dns'].items():
                if values:
                    console.print(f"  {record_type}: {', '.join(map(str, values))}")
        
        # WHOIS
        if results.get('whois'):
            console.print("\n[bold cyan]📋 WHOIS Information:[/bold cyan]")
            for key, value in results['whois'].items():
                if value:
                    console.print(f"  {key}: {value}")
        
        # HTTP Headers
        if results.get('http_headers'):
            console.print("\n[bold cyan]🌐 HTTP Headers:[/bold cyan]")
            for key, value in list(results['http_headers'].items())[:10]:
                console.print(f"  {key}: {value}")
