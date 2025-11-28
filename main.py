#!/usr/bin/env python3
"""
Penetration Testing Toolkit - Main Entry Point
Author: Security Team
Date: November 28, 2025
"""

import sys
import click
from rich.console import Console
from rich.panel import Panel
from pyfiglet import figlet_format

from src.modules.reconnaissance.subdomain_enum import SubdomainEnumerator
from src.modules.reconnaissance.port_scanner import PortScanner
from src.modules.reconnaissance.free_recon import FreeRecon
from src.modules.reconnaissance.shodan_recon import ShodanRecon
from src.modules.reconnaissance.urlscan_recon import URLScanRecon
from src.modules.webapp.vulnerability_scanner import VulnerabilityScanner
from src.modules.webapp.xss_detector import XSSDetector
from src.modules.webapp.sqli_detector import SQLInjectionDetector
from src.modules.network.password_attack import PasswordAttacker
from src.modules.network.wireless import WirelessTester
from src.core.config import Config
from src.core.utils import setup_logging, print_banner

console = Console()

@click.group()
@click.version_option(version='1.0.0')
def cli():
    """Penetration Testing Toolkit - Ethical Hacking Suite"""
    print_banner()

@cli.command()
@click.option('--target', '-t', required=True, help='Target domain')
@click.option('--output', '-o', default='subdomains.txt', help='Output file')
@click.option('--wordlist', '-w', help='Custom wordlist')
@click.option('--threads', default=10, help='Number of threads')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def subdomain(target, output, wordlist, threads, verbose):
    """Subdomain enumeration module"""
    console.print(f"[bold cyan]Starting subdomain enumeration for: {target}[/bold cyan]")
    
    enumerator = SubdomainEnumerator(target, threads=threads, verbose=verbose)
    
    if wordlist:
        enumerator.set_wordlist(wordlist)
    
    subdomains = enumerator.enumerate()
    
    # Save results
    with open(output, 'w') as f:
        for sub in subdomains:
            f.write(f"{sub}\n")
    
    console.print(f"[bold green]✓ Found {len(subdomains)} subdomains[/bold green]")
    console.print(f"[bold green]✓ Results saved to: {output}[/bold green]")

@cli.command()
@click.option('--target', '-t', required=True, help='Target domain or IP')
@click.option('--ports', '-p', default='1-1000', help='Port range (e.g., 1-1000 or 80,443)')
@click.option('--output', '-o', default='portscan.txt', help='Output file')
@click.option('--threads', default=50, help='Number of threads')
@click.option('--timeout', default=1, help='Connection timeout')
@click.option('--nmap/--no-nmap', default=True, help='Use Nmap for advanced scanning (OS detection, service versioning)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def portscan(target, ports, output, threads, timeout, nmap, verbose):
    """Port scanning with Nmap integration for OS detection and service versioning"""
    console.print(f"[bold cyan]Starting port scan for: {target}[/bold cyan]")
    
    scanner = PortScanner(target, threads=threads, timeout=timeout, verbose=verbose, use_nmap=nmap)
    results = scanner.scan(ports)
    
    # Display results
    scanner.display_results(results)
    
    # Save results
    scanner.save_results(results, output)
    
    console.print(f"[bold green]✓ Results saved to: {output}[/bold green]")



@cli.command()
@click.option('--url', '-u', required=True, help='Target URL')
@click.option('--scan-type', default='full', help='Scan type: quick, full, custom')
@click.option('--output', '-o', default='vulnscan.json', help='Output file')
@click.option('--threads', default=5, help='Number of threads')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def vulnscan(url, scan_type, output, threads, verbose):
    """Vulnerability scanning module"""
    console.print(f"[bold cyan]Starting vulnerability scan for: {url}[/bold cyan]")
    
    scanner = VulnerabilityScanner(url, threads=threads, verbose=verbose)
    results = scanner.scan(scan_type=scan_type)
    
    # Display results
    scanner.display_results(results)
    
    # Save results
    scanner.save_results(results, output)
    
    console.print(f"[bold green]✓ Results saved to: {output}[/bold green]")

@cli.command()
@click.option('--url', '-u', required=True, help='Target URL with parameters')
@click.option('--method', default='GET', help='HTTP method: GET, POST')
@click.option('--data', help='POST data (for POST requests)')
@click.option('--level', default=2, help='Test level: 1 (basic), 2 (moderate), 3 (aggressive)')
@click.option('--output', '-o', default='xss_results.json', help='Output file')
def xss(url, method, data, level, output):
    """XSS vulnerability detection"""
    console.print(f"[bold cyan]Starting XSS detection for: {url}[/bold cyan]")
    
    detector = XSSDetector(url, method=method, data=data)
    results = detector.test(level=level)
    
    # Display results
    detector.display_results(results)
    
    # Save results
    detector.save_results(results, output)

@cli.command()
@click.option('--url', '-u', required=True, help='Target URL with parameters')
@click.option('--method', default='GET', help='HTTP method: GET, POST')
@click.option('--data', help='POST data (for POST requests)')
@click.option('--level', default=2, help='Test level: 1 (basic), 2 (moderate), 3 (aggressive)')
@click.option('--dbms', help='Target DBMS: mysql, mssql, postgresql, oracle')
@click.option('--output', '-o', default='sqli_results.json', help='Output file')
def sqli(url, method, data, level, dbms, output):
    """SQL injection vulnerability detection"""
    console.print(f"[bold cyan]Starting SQL injection detection for: {url}[/bold cyan]")
    
    detector = SQLInjectionDetector(url, method=method, data=data, dbms=dbms)
    results = detector.test(level=level)
    
    # Display results
    detector.display_results(results)
    
    # Save results
    detector.save_results(results, output)

@cli.command()
@click.option('--target', '-t', required=True, help='Target (e.g., ssh://192.168.1.1)')
@click.option('--user', '-u', required=True, help='Username')
@click.option('--wordlist', '-w', required=True, help='Password wordlist')
@click.option('--threads', default=5, help='Number of threads')
@click.option('--output', '-o', default='password_results.txt', help='Output file')
def password(target, user, wordlist, threads, output):
    """Password attack module"""
    console.print(f"[bold cyan]Starting password attack for: {target}[/bold cyan]")
    console.print("[bold yellow]⚠ Use only on authorized systems![/bold yellow]")
    
    attacker = PasswordAttacker(target, user, wordlist, threads=threads)
    result = attacker.attack()
    
    if result:
        console.print(f"[bold green]✓ Password found: {result['password']}[/bold green]")
        with open(output, 'w') as f:
            f.write(f"Target: {target}\n")
            f.write(f"Username: {user}\n")
            f.write(f"Password: {result['password']}\n")
    else:
        console.print("[bold red]✗ Password not found[/bold red]")

@cli.command()
@click.option('--interface', '-i', help='Wireless interface (e.g., wlan0)')
@click.option('--scan', is_flag=True, help='Scan for networks')
@click.option('--target', '-t', help='Target BSSID')
@click.option('--wordlist', '-w', help='Password wordlist for WPA cracking')
@click.option('--output', '-o', default='wireless_results.txt', help='Output file')
def wireless(interface, scan, target, wordlist, output):
    """Wireless security testing module"""
    console.print("[bold cyan]Starting wireless security testing[/bold cyan]")
    console.print("[bold yellow]⚠ Use only on authorized networks![/bold yellow]")
    
    tester = WirelessTester(interface)
    
    if scan:
        networks = tester.scan_networks()
        tester.display_networks(networks)
        tester.save_results(networks, output)
    elif target and wordlist:
        result = tester.crack_wpa(target, wordlist)
        if result:
            console.print(f"[bold green]✓ Password found: {result}[/bold green]")
    else:
        console.print("[bold red]Please specify --scan or provide --target and --wordlist[/bold red]")

@cli.command()
@click.option('--target', '-t', required=True, help='Target domain or IP')
@click.option('--method', '-m', type=click.Choice(['free', 'shodan', 'urlscan']), default='free', help='Recon method (free=DNS/WHOIS, shodan=IP intel, urlscan=website analysis)')
@click.option('--output', '-o', help='Output JSON file')
def recon(target, method, output):
    """Comprehensive reconnaissance module"""
    console.print(f"[bold cyan]Starting reconnaissance on: {target}[/bold cyan]")
    
    config = Config()
    
    if method == 'free':
        console.print("[bold green]Using FREE reconnaissance (no API keys needed)[/bold green]")
        recon_tool = FreeRecon()
        results = recon_tool.comprehensive_scan(target)
        recon_tool.display_results(results)
        
    elif method == 'shodan':
        console.print("[bold cyan]Using Shodan API[/bold cyan]")
        api_key = config.get('shodan', 'api_key')
        if not api_key:
            console.print("[bold red]✗ Shodan API key not found in config.yaml[/bold red]")
            return
        recon_tool = ShodanRecon(api_key)
        
        # For Shodan, check if target is IP or domain
        import re
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            # It's an IP
            results = recon_tool.get_host_info(target)
            console.print("\n[bold cyan]Shodan Host Information:[/bold cyan]")
            console.print(f"  IP: {results.get('ip_str', 'N/A')}")
            console.print(f"  Organization: {results.get('org', 'N/A')}")
            console.print(f"  Country: {results.get('country_name', 'N/A')}")
            console.print(f"  Open Ports: {results.get('ports', [])}")
        else:
            # It's a domain, do comprehensive scan
            results = recon_tool.comprehensive_scan(target)
            recon_tool.display_results(results)
            
    elif method == 'urlscan':
        console.print("[bold cyan]Using URLScan.io[/bold cyan]")
        # Add http:// if not present
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Get API key properly
        urlscan_config = config.get('urlscan')
        api_key = urlscan_config.get('api_key') if urlscan_config else None
        
        if api_key:
            console.print("[green]✓ Using API key from config[/green]")
        else:
            console.print("[yellow]⚠ No API key found, using free tier[/yellow]")
        
        recon_tool = URLScanRecon(api_key=api_key)
        results = recon_tool.scan_url(target)
        recon_tool.display_results(results)
    
    if output and hasattr(recon_tool, 'save_results'):
        recon_tool.save_results(output)

@cli.command()
def disclaimer():
    """Display legal disclaimer"""
    disclaimer_text = """
    LEGAL DISCLAIMER
    
    This tool is designed for educational purposes and authorized security testing only.
    
    You must obtain explicit written permission before testing any systems you do not own.
    
    Unauthorized access to computer systems is illegal under laws including:
    - Computer Fraud and Abuse Act (CFAA) in the United States
    - Computer Misuse Act in the United Kingdom
    - Similar laws in other jurisdictions
    
    By using this tool, you agree to:
    1. Only test systems you own or have authorization to test
    2. Comply with all applicable laws and regulations
    3. Take full responsibility for your actions
    4. Not use this tool for malicious purposes
    
    The authors and contributors of this tool:
    - Are not responsible for any misuse
    - Do not condone illegal activities
    - Provide this tool "AS IS" without warranty
    
    Use at your own risk.
    """
    
    console.print(Panel(disclaimer_text, title="⚠️  LEGAL DISCLAIMER", border_style="red"))

if __name__ == '__main__':
    cli()
