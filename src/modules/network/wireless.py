"""
Wireless Security Testing Module
WiFi network scanning and security testing
"""

import subprocess
import re
import platform
from typing import List, Dict, Optional
import logging
from rich.console import Console
from rich.table import Table

console = Console()
logger = logging.getLogger(__name__)

class WirelessTester:
    """Wireless network security testing"""
    
    def __init__(self, interface: str = None):
        self.interface = interface or self._get_default_interface()
        self.os_type = platform.system()
        
        if not self.interface:
            console.print("[yellow]⚠ No wireless interface specified[/yellow]")
    
    def _get_default_interface(self) -> Optional[str]:
        """Get default wireless interface"""
        try:
            if platform.system() == 'Linux':
                result = subprocess.run(['iwconfig'], capture_output=True, text=True)
                # Parse iwconfig output to find wireless interfaces
                for line in result.stdout.split('\n'):
                    if 'IEEE 802.11' in line:
                        return line.split()[0]
            elif platform.system() == 'Windows':
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Name' in line:
                        return line.split(':')[1].strip()
        except:
            pass
        
        return None
    
    def scan_networks(self) -> List[Dict]:
        """Scan for wireless networks"""
        console.print(f"[bold cyan]Scanning wireless networks on {self.interface}...[/bold cyan]\n")
        
        networks = []
        
        try:
            if self.os_type == 'Linux':
                networks = self._scan_linux()
            elif self.os_type == 'Windows':
                networks = self._scan_windows()
            elif self.os_type == 'Darwin':  # macOS
                networks = self._scan_macos()
            else:
                console.print(f"[red]OS not supported: {self.os_type}[/red]")
        
        except Exception as e:
            logger.error(f"Error scanning networks: {e}")
            console.print(f"[red]Error: {e}[/red]")
        
        return networks
    
    def _scan_linux(self) -> List[Dict]:
        """Scan networks on Linux"""
        networks = []
        
        try:
            # Use iwlist to scan
            result = subprocess.run(
                ['sudo', 'iwlist', self.interface, 'scan'],
                capture_output=True, text=True, timeout=30
            )
            
            # Parse output
            current_network = {}
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if 'Cell' in line and 'Address:' in line:
                    if current_network:
                        networks.append(current_network)
                    current_network = {
                        'bssid': line.split('Address: ')[1].strip(),
                        'essid': '',
                        'channel': '',
                        'encryption': 'Open',
                        'signal': ''
                    }
                
                elif 'ESSID:' in line:
                    essid = line.split('ESSID:')[1].strip().strip('"')
                    current_network['essid'] = essid
                
                elif 'Channel:' in line:
                    channel = line.split('Channel:')[1].strip()
                    current_network['channel'] = channel
                
                elif 'Encryption key:' in line:
                    if 'on' in line:
                        current_network['encryption'] = 'WPA/WPA2'
                
                elif 'Signal level=' in line:
                    signal = line.split('Signal level=')[1].split()[0]
                    current_network['signal'] = signal
            
            if current_network:
                networks.append(current_network)
        
        except subprocess.TimeoutExpired:
            console.print("[yellow]Scan timeout[/yellow]")
        except Exception as e:
            logger.error(f"Linux scan error: {e}")
        
        return networks
    
    def _scan_windows(self) -> List[Dict]:
        """Scan networks on Windows"""
        networks = []
        
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True, text=True
            )
            
            current_network = {}
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if 'SSID' in line and ':' in line:
                    if current_network:
                        networks.append(current_network)
                    ssid = line.split(':', 1)[1].strip()
                    current_network = {
                        'essid': ssid,
                        'bssid': '',
                        'channel': '',
                        'encryption': 'Unknown',
                        'signal': ''
                    }
                
                elif 'BSSID' in line and ':' in line:
                    bssid = line.split(':', 1)[1].strip()
                    current_network['bssid'] = bssid
                
                elif 'Signal' in line:
                    signal = line.split(':')[1].strip()
                    current_network['signal'] = signal
                
                elif 'Authentication' in line:
                    auth = line.split(':')[1].strip()
                    current_network['encryption'] = auth
                
                elif 'Channel' in line:
                    channel = line.split(':')[1].strip()
                    current_network['channel'] = channel
            
            if current_network:
                networks.append(current_network)
        
        except Exception as e:
            logger.error(f"Windows scan error: {e}")
        
        return networks
    
    def _scan_macos(self) -> List[Dict]:
        """Scan networks on macOS"""
        networks = []
        
        try:
            result = subprocess.run(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'],
                capture_output=True, text=True
            )
            
            lines = result.stdout.split('\n')[1:]  # Skip header
            
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 6:
                        networks.append({
                            'essid': parts[0],
                            'bssid': parts[1],
                            'signal': parts[2],
                            'channel': parts[3],
                            'encryption': parts[6] if len(parts) > 6 else 'Unknown'
                        })
        
        except Exception as e:
            logger.error(f"macOS scan error: {e}")
        
        return networks
    
    def display_networks(self, networks: List[Dict]):
        """Display scanned networks"""
        if not networks:
            console.print("[yellow]No networks found[/yellow]")
            return
        
        table = Table(title="\nWireless Networks", show_header=True, header_style="bold magenta")
        table.add_column("ESSID", style="cyan")
        table.add_column("BSSID", style="yellow")
        table.add_column("Channel", style="green")
        table.add_column("Signal", style="blue")
        table.add_column("Encryption", style="red")
        
        for network in networks:
            table.add_row(
                network.get('essid', 'Hidden'),
                network.get('bssid', 'N/A'),
                network.get('channel', 'N/A'),
                network.get('signal', 'N/A'),
                network.get('encryption', 'Unknown')
            )
        
        console.print(table)
        console.print(f"\n[bold green]Found {len(networks)} networks[/bold green]")
    
    def crack_wpa(self, target_bssid: str, wordlist: str) -> Optional[str]:
        """Crack WPA/WPA2 password (Linux only, requires aircrack-ng)"""
        console.print(f"[bold cyan]Attempting to crack WPA for: {target_bssid}[/bold cyan]")
        console.print("[bold red]⚠ Only use on authorized networks![/bold red]\n")
        
        if self.os_type != 'Linux':
            console.print("[red]WPA cracking only supported on Linux[/red]")
            return None
        
        console.print("[yellow]This feature requires aircrack-ng suite and captured handshake[/yellow]")
        console.print("[yellow]Please capture handshake first using: airodump-ng[/yellow]")
        
        # This is a placeholder - actual implementation requires:
        # 1. Captured handshake file
        # 2. aircrack-ng installed
        # 3. Proper implementation with subprocess
        
        return None
    
    def save_results(self, networks: List[Dict], filename: str):
        """Save scan results"""
        with open(filename, 'w') as f:
            f.write("Wireless Network Scan Results\n")
            f.write("=" * 80 + "\n\n")
            
            for network in networks:
                f.write(f"ESSID: {network.get('essid', 'Hidden')}\n")
                f.write(f"BSSID: {network.get('bssid', 'N/A')}\n")
                f.write(f"Channel: {network.get('channel', 'N/A')}\n")
                f.write(f"Signal: {network.get('signal', 'N/A')}\n")
                f.write(f"Encryption: {network.get('encryption', 'Unknown')}\n")
                f.write("-" * 80 + "\n")
        
        console.print(f"[green]Results saved to: {filename}[/green]")
