"""
URLScan.io Reconnaissance Module
Free website scanner and analyzer
"""

import requests
import time
from typing import Dict, Optional
from rich.console import Console
from rich.panel import Panel
from src.core.utils import save_json

console = Console()

class URLScanRecon:
    """URLScan.io website analysis tool"""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize URLScan client
        
        Args:
            api_key: Optional API key for higher limits (free tier works without key)
        """
        self.base_url = "https://urlscan.io/api/v1"
        self.headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        }
        if api_key:
            self.headers['API-Key'] = api_key
        self.results = {}
        console.print("[green]✓ URLScan.io initialized (free tier available)[/green]")
    
    def submit_scan(self, url: str, visibility: str = "public") -> Optional[str]:
        """Submit URL for scanning
        
        Args:
            url: URL to scan
            visibility: 'public' or 'private' (private requires API key)
            
        Returns:
            UUID of the scan
        """
        console.print(f"[cyan]🔍 Submitting URL to URLScan.io: {url}[/cyan]")
        
        try:
            data = {
                "url": url,
                "visibility": visibility
            }
            
            response = requests.post(
                f"{self.base_url}/scan/",
                json=data,
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                uuid = result.get('uuid')
                console.print(f"[green]✓ Scan submitted successfully (UUID: {uuid})[/green]")
                return uuid
            else:
                console.print(f"[red]✗ Scan submission failed: {response.status_code}[/red]")
                console.print(f"[red]  {response.text}[/red]")
                return None
                
        except Exception as e:
            console.print(f"[red]✗ Error submitting scan: {e}[/red]")
            return None
    
    def get_scan_result(self, uuid: str, wait: bool = True, max_wait: int = 60) -> Dict:
        """Get scan results
        
        Args:
            uuid: Scan UUID
            wait: Whether to wait for scan to complete
            max_wait: Maximum seconds to wait
            
        Returns:
            Scan results dictionary
        """
        console.print(f"[cyan]⏳ Waiting for scan to complete...[/cyan]")
        
        waited = 0
        while wait and waited < max_wait:
            try:
                response = requests.get(
                    f"{self.base_url}/result/{uuid}/",
                    headers=self.headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    console.print(f"[green]✓ Scan completed![/green]")
                    return response.json()
                elif response.status_code == 404:
                    # Scan still processing
                    time.sleep(5)
                    waited += 5
                    console.print(f"[yellow]  Still processing... ({waited}s)[/yellow]")
                else:
                    console.print(f"[red]✗ Error getting results: {response.status_code}[/red]")
                    break
                    
            except Exception as e:
                console.print(f"[red]✗ Error: {e}[/red]")
                break
        
        return {}
    
    def scan_url(self, url: str) -> Dict:
        """Perform complete URL scan
        
        Args:
            url: URL to scan
            
        Returns:
            Scan results
        """
        # Submit scan
        uuid = self.submit_scan(url)
        if not uuid:
            return {}
        
        # Get results
        results = self.get_scan_result(uuid, wait=True, max_wait=60)
        
        if results:
            # Extract useful information
            parsed_results = {
                'url': url,
                'uuid': uuid,
                'scan_time': results.get('task', {}).get('time', 'N/A'),
                'page_title': results.get('page', {}).get('title', 'N/A'),
                'server': results.get('page', {}).get('server', 'N/A'),
                'ip': results.get('page', {}).get('ip', 'N/A'),
                'country': results.get('page', {}).get('country', 'N/A'),
                'domain': results.get('page', {}).get('domain', 'N/A'),
                'technologies': [],
                'certificates': [],
                'links': []
            }
            
            # Extract technologies
            meta = results.get('meta', {})
            if 'processors' in meta:
                tech_data = meta['processors'].get('wappa', {})
                if 'data' in tech_data:
                    for tech in tech_data['data']:
                        parsed_results['technologies'].append({
                            'name': tech.get('app', 'Unknown'),
                            'categories': tech.get('categories', [])
                        })
            
            # Extract certificate info
            if 'lists' in results:
                certs = results['lists'].get('certificates', [])
                parsed_results['certificates'] = certs
                
                # Extract links
                links = results['lists'].get('linkDomains', [])
                parsed_results['links'] = links[:20]  # Top 20 links
            
            return parsed_results
        
        return {}
    
    def display_results(self, results: Dict):
        """Display scan results"""
        if not results:
            console.print("[yellow]No results to display[/yellow]")
            return
        
        # Summary
        summary = Panel.fit(
            f"[bold green]URLScan.io Analysis Complete[/bold green]\n\n"
            f"🌐 URL: [cyan]{results.get('url', 'N/A')}[/cyan]\n"
            f"📱 IP: [cyan]{results.get('ip', 'N/A')}[/cyan]\n"
            f"🌍 Country: [cyan]{results.get('country', 'N/A')}[/cyan]\n"
            f"🖥️  Server: [cyan]{results.get('server', 'N/A')}[/cyan]\n"
            f"💻 Technologies: [cyan]{len(results.get('technologies', []))}[/cyan]",
            title=f"📊 {results.get('page_title', 'Website Analysis')}",
            border_style="green"
        )
        console.print(summary)
        
        # Technologies
        if results.get('technologies'):
            console.print("\n[bold cyan]💻 Detected Technologies:[/bold cyan]")
            for tech in results['technologies'][:15]:
                cats = tech.get('categories', [])
                if isinstance(cats, list) and cats:
                    # Handle both string and dict categories
                    cat_names = []
                    for cat in cats:
                        if isinstance(cat, dict):
                            cat_names.append(cat.get('name', str(cat)))
                        else:
                            cat_names.append(str(cat))
                    cats_str = ', '.join(cat_names)
                else:
                    cats_str = 'Unknown'
                console.print(f"  • [green]{tech.get('name', 'Unknown')}[/green] ({cats_str})")
        
        # Links
        if results.get('links'):
            console.print(f"\n[bold cyan]🔗 External Links ({len(results['links'])}):[/bold cyan]")
            for link in results['links'][:10]:
                console.print(f"  • [green]{link}[/green]")
    
    def save_results(self, filename: str):
        """Save results to JSON file"""
        if self.results:
            filepath = save_json(self.results, filename)
            console.print(f"\n[bold green]✓ Results saved to: output/{filename}[/bold green]")
            return filepath
        return None
