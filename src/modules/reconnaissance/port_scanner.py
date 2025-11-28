"""
Port Scanner Module
Fast TCP/UDP port scanning with service detection and Nmap integration
"""

import socket
import concurrent.futures
from typing import List, Dict, Tuple, Optional
import logging
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from src.core.utils import parse_ports, save_json

console = Console()
logger = logging.getLogger(__name__)

# Try to import nmap for advanced scanning
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logger.warning("python-nmap not installed. Advanced OS detection will be disabled.")

class PortScanner:
    """Advanced port scanner with service detection and Nmap integration"""
    
    # Common service mapping
    COMMON_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
        6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
    }
    
    def __init__(self, target: str, threads: int = 50, timeout: int = 1, verbose: bool = False, use_nmap: bool = True):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.use_nmap = use_nmap and NMAP_AVAILABLE
        self.open_ports: List[Dict] = []
        self.os_info: Optional[Dict] = None
        
        if use_nmap and not NMAP_AVAILABLE:
            console.print("[yellow]⚠ Nmap not available, falling back to socket scanning[/yellow]")
    
    def _scan_port(self, port: int) -> Tuple[int, bool, str]:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                service = self._identify_service(port)
                if self.verbose:
                    console.print(f"[green]✓[/green] Port {port} is OPEN ({service})")
                return (port, True, service)
            
            return (port, False, '')
        except socket.gaierror:
            logger.error(f"Hostname could not be resolved: {self.target}")
            return (port, False, '')
        except socket.error as e:
            if self.verbose:
                logger.debug(f"Error scanning port {port}: {e}")
            return (port, False, '')
    
    def _identify_service(self, port: int) -> str:
        """Identify service running on port"""
        # Check common ports first
        if port in self.COMMON_PORTS:
            return self.COMMON_PORTS[port]
        
        # Try banner grabbing
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            
            # Send HTTP request for web servers
            if port in [80, 8080, 8000, 8888]:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if 'Server:' in banner:
                    return banner.split('Server:')[1].split('\r\n')[0].strip()
            
            # Try to receive banner
            sock.send(b'\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Parse banner for service info
            if banner:
                return banner.split('\n')[0][:50]
        except:
            pass
        
        return 'Unknown'
    
    def _nmap_scan(self, ports: str = '1-1000') -> List[Dict]:
        """Perform advanced Nmap scan with service version and OS detection"""
        if not NMAP_AVAILABLE:
            logger.error("Nmap is not available")
            return []
        
        try:
            nm = nmap.PortScanner()
            
            # Parse port range for nmap format
            port_list = parse_ports(ports)
            if len(port_list) > 1000:
                # For large ranges, use nmap's range format
                port_range = f"{min(port_list)}-{max(port_list)}"
            else:
                # For specific ports, list them
                port_range = ','.join(map(str, port_list))
            
            console.print(f"[bold cyan]🔍 Starting Nmap scan on {self.target}...[/bold cyan]")
            console.print(f"[cyan]Port range: {port_range}[/cyan]")
            console.print(f"[cyan]Options: Service version detection (-sV) + OS detection (-O)[/cyan]\n")
            
            # Perform scan with service version detection and OS detection
            # -sV: Version detection, -O: OS detection, -T4: Faster timing
            try:
                nm.scan(self.target, port_range, arguments='-sV -O -T4 --version-intensity 5')
            except:
                # If OS detection fails (requires root), try without it
                console.print("[yellow]⚠ OS detection requires administrator privileges, continuing without it...[/yellow]")
                nm.scan(self.target, port_range, arguments='-sV -T4 --version-intensity 5')
            
            results = []
            
            # Check if host is up - all_hosts() returns IPs, not hostnames
            hosts = nm.all_hosts()
            if not hosts:
                console.print(f"[yellow]⚠ Host {self.target} appears to be down or unreachable[/yellow]")
                return []
            
            # Get the first host (could be IP or resolved hostname)
            scanned_host = hosts[0]
            
            # Extract OS information if available
            if 'osmatch' in nm[scanned_host] and nm[scanned_host]['osmatch']:
                self.os_info = {
                    'name': nm[scanned_host]['osmatch'][0]['name'],
                    'accuracy': nm[scanned_host]['osmatch'][0]['accuracy'],
                    'line': nm[scanned_host]['osmatch'][0].get('line', 'N/A')
                }
                console.print(f"[green]✓ OS Detection: {self.os_info['name']} (Accuracy: {self.os_info['accuracy']}%)[/green]")
            
            # Process scan results
            for proto in nm[scanned_host].all_protocols():
                ports = nm[scanned_host][proto].keys()
                
                for port in ports:
                    port_info = nm[scanned_host][proto][port]
                    
                    if port_info['state'] == 'open':
                        service_name = port_info.get('name', 'unknown')
                        service_product = port_info.get('product', '')
                        service_version = port_info.get('version', '')
                        service_extrainfo = port_info.get('extrainfo', '')
                        
                        # Build detailed service string
                        service_details = service_name
                        if service_product:
                            service_details = f"{service_product}"
                            if service_version:
                                service_details += f" {service_version}"
                            if service_extrainfo:
                                service_details += f" ({service_extrainfo})"
                        
                        results.append({
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': service_details,
                            'product': service_product,
                            'version': service_version,
                            'extrainfo': service_extrainfo
                        })
            
            return results
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            console.print(f"[red]✗ Nmap scan failed: {e}[/red]")
            console.print("[yellow]Falling back to socket scanning...[/yellow]")
            return []
    
    def scan(self, ports: str = '1-1000') -> List[Dict]:
        """Scan ports on target"""
        console.print(f"[bold cyan]Scanning {self.target}...[/bold cyan]")
        
        # Try Nmap scan first if enabled
        if self.use_nmap:
            nmap_results = self._nmap_scan(ports)
            if nmap_results:
                self.open_ports = nmap_results
                return self.open_ports
            # If Nmap fails, fall through to socket scanning
        
        # Fallback to socket-based scanning
        console.print("[cyan]Using socket-based scanning...[/cyan]")
        
        # Parse port range
        port_list = parse_ports(ports)
        total_ports = len(port_list)
        
        console.print(f"[cyan]Scanning {total_ports} ports with {self.threads} threads...[/cyan]\n")
        
        self.open_ports = []
        
        # Scan ports with progress bar
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=total_ports)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_port = {
                    executor.submit(self._scan_port, port): port
                    for port in port_list
                }
                
                for future in concurrent.futures.as_completed(future_to_port):
                    port, is_open, service = future.result()
                    
                    if is_open:
                        self.open_ports.append({
                            'port': port,
                            'service': service,
                            'state': 'open'
                        })
                    
                    progress.update(task, advance=1)
        
        return self.open_ports
    
    def display_results(self, results: List[Dict]):
        """Display scan results in table format"""
        if not results:
            console.print("[yellow]No open ports found[/yellow]")
            return
        
        # Display OS information if available
        if self.os_info:
            from rich.panel import Panel
            os_panel = Panel(
                f"[bold green]{self.os_info['name']}[/bold green]\n"
                f"Accuracy: [cyan]{self.os_info['accuracy']}%[/cyan]",
                title="🖥️  Operating System Detection",
                border_style="green"
            )
            console.print(os_panel)
            console.print()
        
        table = Table(title=f"\n🔍 Open Ports on {self.target}", show_header=True, header_style="bold magenta")
        table.add_column("Port", style="cyan", justify="right", width=8)
        table.add_column("Protocol", style="blue", width=10)
        table.add_column("State", style="green", width=10)
        table.add_column("Service", style="yellow")
        
        for result in sorted(results, key=lambda x: x['port']):
            # Check if we have detailed Nmap info or basic socket info
            protocol = result.get('protocol', 'tcp')
            
            table.add_row(
                str(result['port']),
                protocol,
                result['state'],
                result['service']
            )
        
        console.print(table)
        console.print(f"\n[bold green]✓ Found {len(results)} open ports[/bold green]")
        
        # Show version info summary if available
        if any('product' in r for r in results):
            versioned = sum(1 for r in results if r.get('product'))
            console.print(f"[cyan]ℹ Service version detected on {versioned} ports[/cyan]")
    
    def save_results(self, results: List[Dict], filename: str):
        """Save results to file"""
        data = {
            'target': self.target,
            'total_ports_scanned': sum(1 for _ in results),
            'open_ports': results,
            'os_detection': self.os_info,
            'scan_config': {
                'threads': self.threads,
                'timeout': self.timeout,
                'nmap_enabled': self.use_nmap
            }
        }
        
        if filename.endswith('.json'):
            save_json(data, filename)
        else:
            # Save as text
            with open(filename, 'w') as f:
                f.write(f"Port Scan Results for {self.target}\n")
                f.write("=" * 50 + "\n\n")
                
                # Write OS info if available
                if self.os_info:
                    f.write(f"Operating System: {self.os_info['name']}\n")
                    f.write(f"Accuracy: {self.os_info['accuracy']}%\n")
                    f.write("=" * 50 + "\n\n")
                
                for result in results:
                    protocol = result.get('protocol', 'tcp')
                    f.write(f"Port: {result['port']}/{protocol}\t State: {result['state']}\t Service: {result['service']}\n")
