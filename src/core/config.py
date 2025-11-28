"""
Configuration management for the toolkit
Supports environment variables for sensitive data
"""

import os
from pathlib import Path
from typing import Dict, Any
import yaml
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Configuration manager with environment variable support"""
    
    def __init__(self, config_file: str = None):
        self.config_file = config_file or self._get_default_config()
        self.config = self._load_config()
    
    def _get_default_config(self) -> str:
        """Get default config file path"""
        return os.path.join(Path(__file__).parent.parent.parent, 'config.yaml')
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f) or {}
        return self._get_default_config_dict()
    
    def _get_default_config_dict(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'general': {
                'timeout': 10,
                'threads': 10,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'delay': 1
            },
            'subdomain': {
                'wordlist': 'data/wordlists/subdomains.txt',
                'dns_servers': ['8.8.8.8', '1.1.1.1'],
                'threads': 10
            },
            'port_scanner': {
                'default_ports': '1-1000',
                'threads': 50,
                'timeout': 1
            },
            'google_dorking': {
                'delay': 5,
                'max_results': 50
            },
            'vulnerability_scanner': {
                'threads': 5,
                'timeout': 10
            },
            'password_attack': {
                'threads': 5,
                'timeout': 5
            },
            'output': {
                'directory': 'output',
                'format': 'json'
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value, checking environment variables first for API keys"""
        # Check environment variables for API keys
        env_mappings = {
            'shodan.api_key': 'SHODAN_API_KEY',
            'urlscan.api_key': 'URLSCAN_API_KEY',
        }
        
        if key in env_mappings:
            env_value = os.getenv(env_mappings[key])
            if env_value:
                return env_value
        
        # Fall back to config file
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split('.')
        config = self.config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
    
    def save(self):
        """Save configuration to file"""
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        with open(self.config_file, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)

# Global config instance
config = Config()
