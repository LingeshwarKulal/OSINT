"""
Subdomain Enumeration Module
Discovers subdomains using multiple techniques
"""

import dns.resolver
import requests
import concurrent.futures
from typing import List, Set
import logging
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()
logger = logging.getLogger(__name__)

class SubdomainEnumerator:
    """Subdomain enumeration using multiple techniques"""
    
    def __init__(self, domain: str, threads: int = 10, verbose: bool = False):
        self.domain = domain
        self.threads = threads
        self.verbose = verbose
        self.found_subdomains: Set[str] = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        
        # Default wordlist
        self.wordlist = self._get_default_wordlist()
    
    def _get_default_wordlist(self) -> List[str]:
        """Get default subdomain wordlist"""
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns', 'm', 'imap', 'test',
            'ns3', 'dns', 'forum', 'blog', 'vpn', 'ns4', 'support', 'dev', 'admin', 'api',
            'cdn', 'portal', 'stage', 'staging', 'app', 'mobile', 'demo', 'shop', 'store',
            'panel', 'secure', 'mysql', 'beta', 'dashboard', 'login', 'remote', 'server',
            'wiki', 'static', 'img', 'images', 'upload', 'download', 'old', 'new', 'web',
            'sql', 'database', 'db', 'git', 'svn', 'backup', 'backups', 'media', 'assets'
        ]
    
    def set_wordlist(self, wordlist_file: str):
        """Set custom wordlist"""
        try:
            with open(wordlist_file, 'r') as f:
                self.wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error loading wordlist: {e}")
    
    def _check_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain exists via DNS lookup"""
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            self.resolver.resolve(full_domain, 'A')
            if self.verbose:
                console.print(f"[green]✓[/green] Found: {full_domain}")
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return False
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error checking {full_domain}: {e}")
            return False
    
    def _dns_bruteforce(self) -> Set[str]:
        """Brute force subdomains using wordlist"""
        console.print(f"[cyan]Starting DNS brute force with {len(self.wordlist)} words...[/cyan]")
        
        found = set()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Brute forcing...", total=len(self.wordlist))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_subdomain = {
                    executor.submit(self._check_subdomain, subdomain): subdomain
                    for subdomain in self.wordlist
                }
                
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    subdomain = future_to_subdomain[future]
                    try:
                        if future.result():
                            found.add(f"{subdomain}.{self.domain}")
                    except Exception as e:
                        logger.error(f"Error processing {subdomain}: {e}")
                    
                    progress.update(task, advance=1)
        
        return found
    
    def _crtsh_search(self) -> Set[str]:
        """Search Certificate Transparency logs via crt.sh"""
        console.print("[cyan]Searching Certificate Transparency logs...[/cyan]")
        
        found = set()
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        # Handle wildcard and newline-separated names
                        names = name.replace('*.', '').split('\n')
                        for n in names:
                            n = n.strip()
                            if n and n.endswith(self.domain):
                                found.add(n)
                                if self.verbose:
                                    console.print(f"[green]✓[/green] Found: {n}")
        except Exception as e:
            logger.error(f"Error searching crt.sh: {e}")
        
        return found
    
    def _threatcrowd_search(self) -> Set[str]:
        """Search ThreatCrowd API"""
        console.print("[cyan]Searching ThreatCrowd API...[/cyan]")
        
        found = set()
        
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                for subdomain in subdomains:
                    found.add(subdomain)
                    if self.verbose:
                        console.print(f"[green]✓[/green] Found: {subdomain}")
        except Exception as e:
            logger.error(f"Error searching ThreatCrowd: {e}")
        
        return found
    
    def _hackertarget_search(self) -> Set[str]:
        """Search HackerTarget API"""
        console.print("[cyan]Searching HackerTarget API...[/cyan]")
        
        found = set()
        
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain and subdomain.endswith(self.domain):
                            found.add(subdomain)
                            if self.verbose:
                                console.print(f"[green]✓[/green] Found: {subdomain}")
        except Exception as e:
            logger.error(f"Error searching HackerTarget: {e}")
        
        return found
    
    def enumerate(self) -> List[str]:
        """Run all enumeration techniques"""
        console.print(f"[bold cyan]Enumerating subdomains for: {self.domain}[/bold cyan]\n")
        
        # DNS Brute Force
        dns_results = self._dns_bruteforce()
        self.found_subdomains.update(dns_results)
        
        # Certificate Transparency
        crt_results = self._crtsh_search()
        self.found_subdomains.update(crt_results)
        
        # ThreatCrowd
        threat_results = self._threatcrowd_search()
        self.found_subdomains.update(threat_results)
        
        # HackerTarget
        hacker_results = self._hackertarget_search()
        self.found_subdomains.update(hacker_results)
        
        # Display results
        console.print(f"\n[bold green]Total subdomains found: {len(self.found_subdomains)}[/bold green]")
        
        if self.found_subdomains:
            console.print("\n[bold cyan]Found subdomains:[/bold cyan]")
            for subdomain in sorted(self.found_subdomains):
                console.print(f"  • {subdomain}")
        
        return sorted(list(self.found_subdomains))
