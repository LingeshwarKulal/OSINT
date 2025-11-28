"""
Utility functions for the toolkit
"""

import os
import sys
import logging
import json
import re
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from pyfiglet import figlet_format
import validators

console = Console()

def setup_logging(log_file: str = 'pentest.log', level: int = logging.INFO):
    """Setup logging configuration"""
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    
    log_path = os.path.join(log_dir, log_file)
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)

def print_banner():
    """Print application banner"""
    banner = figlet_format('PenTest Kit', font='slant')
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[bold yellow]Penetration Testing Toolkit v1.0.0[/bold yellow]")
    console.print("[bold red]⚠  For Authorized Security Testing Only ⚠[/bold red]\n")

def validate_url(url: str) -> bool:
    """Validate URL format"""
    return validators.url(url) == True

def validate_domain(domain: str) -> bool:
    """Validate domain format"""
    return validators.domain(domain) == True

def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    return validators.ipv4(ip) == True or validators.ipv6(ip) == True

def validate_target(target: str) -> bool:
    """
    Validate target (domain or IP address)
    Returns True if target is valid, False otherwise
    """
    # Check if IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    # Check if valid domain
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(domain_pattern, target))

def sanitize_input(input_str: str, allowed_chars: str = r'[a-zA-Z0-9.\-_]') -> str:
    """
    Sanitize user input to prevent injection attacks
    Keeps only alphanumeric, dots, hyphens, and underscores by default
    """
    pattern = f'^{allowed_chars}+$'
    if not re.match(pattern, input_str):
        raise ValueError(f"Invalid input: {input_str}. Only {allowed_chars} allowed.")
    return input_str

def validate_ports(port_string: str) -> bool:
    """
    Validate port string format to prevent injection
    Allows only digits, commas, and hyphens
    """
    return bool(re.match(r'^[\d,\-]+$', port_string.strip()))

def parse_ports(port_string: str) -> List[int]:
    """
    Parse port string to list of ports
    Examples: '80', '80,443', '1-100', '80,443,8000-8100'
    
    Security: Validates input before parsing to prevent injection
    """
    if not validate_ports(port_string):
        raise ValueError(f"Invalid port string format: {port_string}")
    
    ports = []
    
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"Invalid port range: {start}-{end}")
            ports.extend(range(start, end + 1))
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port number: {port}")
            ports.append(port)
    
    return sorted(list(set(ports)))

def save_json(data: Any, filename: str):
    """Save data as JSON"""
    output_dir = 'output'
    os.makedirs(output_dir, exist_ok=True)
    
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4, default=str)
    
    return filepath

def load_json(filename: str) -> Any:
    """Load JSON file"""
    with open(filename, 'r') as f:
        return json.load(f)

def save_text(lines: List[str], filename: str):
    """Save lines to text file"""
    output_dir = 'output'
    os.makedirs(output_dir, exist_ok=True)
    
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w') as f:
        for line in lines:
            f.write(f"{line}\n")
    
    return filepath

def load_wordlist(filename: str) -> List[str]:
    """Load wordlist from file"""
    if not os.path.exists(filename):
        return []
    
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def create_table(title: str, columns: List[str]) -> Table:
    """Create rich table"""
    table = Table(title=title, show_header=True, header_style="bold magenta")
    
    for column in columns:
        table.add_column(column)
    
    return table

def print_success(message: str):
    """Print success message"""
    console.print(f"[bold green]✓ {message}[/bold green]")

def print_error(message: str):
    """Print error message"""
    console.print(f"[bold red]✗ {message}[/bold red]")

def print_info(message: str):
    """Print info message"""
    console.print(f"[bold blue]ℹ {message}[/bold blue]")

def print_warning(message: str):
    """Print warning message"""
    console.print(f"[bold yellow]⚠ {message}[/bold yellow]")

def get_timestamp() -> str:
    """Get current timestamp"""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to remove invalid characters"""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename

def ensure_directory(directory: str):
    """Ensure directory exists"""
    os.makedirs(directory, exist_ok=True)

def get_file_size(filepath: str) -> str:
    """Get human-readable file size"""
    size = os.path.getsize(filepath)
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    
    return f"{size:.2f} PB"

class ProgressTracker:
    """Simple progress tracker"""
    
    def __init__(self, total: int, description: str = "Progress"):
        self.total = total
        self.current = 0
        self.description = description
    
    def update(self, increment: int = 1):
        """Update progress"""
        self.current += increment
        percentage = (self.current / self.total) * 100
        console.print(f"{self.description}: {self.current}/{self.total} ({percentage:.1f}%)")
    
    def complete(self):
        """Mark as complete"""
        console.print(f"[bold green]{self.description}: Complete! ({self.total}/{self.total})[/bold green]")
