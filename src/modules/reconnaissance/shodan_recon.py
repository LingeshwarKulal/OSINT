"""
Shodan.io Reconnaissance Module
Alternative to Censys with simpler API authentication
"""

import logging
import requests
from typing import List, Dict, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from src.core.utils import save_json

console = Console()
logger = logging.getLogger(__name__)

class ShodanRecon:
    """Shodan.io reconnaissance tool using direct API"""
    
    def __init__(self, api_key: str):
        """Initialize Shodan API client"""
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"
        self.results = {}
        
        console.print("[green]✓ Shodan API initialized[/green]")
        console.print("[yellow]  Get your API key from: https://account.shodan.io/[/yellow]")
    
    def search_hosts(self, query: str, max_results: int = 50) -> List[Dict]:
        """Search for hosts using Shodan API"""
        console.print(f"[cyan]🔍 Searching Shodan for: {query}[/cyan]")
        
        try:
            params = {
                "key": self.api_key,
                "query": query,
                "limit": min(max_results, 100)
            }
            
            response = requests.get(
                f"{self.base_url}/shodan/host/search",
                params=params,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            results = data.get("matches", [])
            
            console.print(f"[green]✓ Found {len(results)} hosts[/green]")
            return results
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"Shodan API error: {e}")
            console.print(f"[red]✗ API request failed: {e}[/red]")
            if hasattr(e.response, 'text'):
                console.print(f"[red]  Response: {e.response.text}[/red]")
            return []
        except Exception as e:
            logger.error(f"Shodan search error: {e}")
            console.print(f"[red]✗ Search failed: {e}[/red]")
            return []
    
    def get_host_info(self, ip: str) -> Dict:
        """Get detailed information about a specific IP"""
        console.print(f"[cyan]📡 Getting host information for: {ip}[/cyan]")
        
        try:
            params = {"key": self.api_key}
            
            response = requests.get(
                f"{self.base_url}/shodan/host/{ip}",
                params=params,
                timeout=30
            )
            response.raise_for_status()
            
            host = response.json()
            console.print(f"[green]✓ Retrieved host information[/green]")
            return host
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"Shodan host lookup error: {e}")
            console.print(f"[yellow]⚠ Host {ip} not found or error: {e}[/yellow]")
            return {}
        except Exception as e:
            logger.error(f"Shodan host lookup error: {e}")
            console.print(f"[yellow]⚠ Error: {e}[/yellow]")
            return {}
    
    def comprehensive_scan(self, domain: str) -> Dict:
        """Perform comprehensive reconnaissance on a domain"""
        console.print(Panel.fit(
            f"[bold cyan]Starting Shodan Reconnaissance[/bold cyan]\n"
            f"Target: [yellow]{domain}[/yellow]",
            border_style="cyan"
        ))
        
        results = {
            'domain': domain,
            'hosts': [],
            'services': [],
            'open_ports': []
        }
        
        # Search for hosts related to domain
        query = f"hostname:{domain}"
        hosts = self.search_hosts(query, max_results=50)
        
        for host in hosts:
            ip = host.get('ip_str', 'N/A')
            port = host.get('port', 'N/A')
            
            results['hosts'].append({
                'ip': ip,
                'port': port,
                'organization': host.get('org', 'N/A'),
                'location': host.get('location', {}),
                'domains': host.get('domains', []),
                'hostnames': host.get('hostnames', [])
            })
            
            results['open_ports'].append({
                'ip': ip,
                'port': port,
                'protocol': host.get('transport', 'tcp'),
                'service': host.get('product', 'unknown')
            })
        
        self.results = results
        return results
    
    def display_results(self, results: Dict):
        """Display scan results"""
        domain = results.get('domain', 'Unknown')
        
        summary = Panel.fit(
            f"[bold green]Shodan Reconnaissance Complete[/bold green]\n\n"
            f"🌐 Hosts Found: [cyan]{len(results.get('hosts', []))}[/cyan]\n"
            f"🔓 Open Ports: [cyan]{len(results.get('open_ports', []))}[/cyan]",
            title=f"📊 Summary for {domain}",
            border_style="green"
        )
        console.print(summary)
        
        # Hosts table
        if results.get('hosts'):
            console.print("\n[bold cyan]🖥️  Discovered Hosts[/bold cyan]")
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("IP Address", style="cyan")
            table.add_column("Port", style="yellow")
            table.add_column("Organization", style="green")
            
            for host in results['hosts'][:20]:
                table.add_row(
                    host.get('ip', 'N/A'),
                    str(host.get('port', 'N/A')),
                    host.get('organization', 'N/A')[:40]
                )
            
            console.print(table)
    
    def save_results(self, filename: str):
        """Save results to JSON file"""
        if self.results:
            filepath = save_json(self.results, filename)
            console.print(f"\n[bold green]✓ Results saved to: output/{filename}[/bold green]")
            return filepath
        return None
