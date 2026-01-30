"""
Configuration Module

Centralized configuration management for QuShield.

Example:
    >>> from qushield.utils.config import get_config
    >>> config = get_config()
    >>> print(config.scan_timeout)
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class Config:
    """
    QuShield configuration settings.
    
    Attributes can be overridden via environment variables with QUSHIELD_ prefix.
    """
    # Scanning settings
    scan_timeout: int = 30
    max_concurrent_scans: int = 5
    max_assets_per_scan: int = 100
    
    # Discovery settings
    use_ct_logs: bool = True
    use_subdomain_enum: bool = True
    verify_dns: bool = False
    ct_log_timeout: int = 60
    
    # Output settings
    output_dir: str = "outputs"
    log_dir: str = "logs"
    save_json: bool = True
    save_cbom: bool = True
    
    # Logging settings
    log_level: str = "INFO"
    json_logs: bool = True
    console_output: bool = True
    
    # Certification settings
    certification_validity_days: int = 90
    
    # Extended discovery settings
    port_scan_enabled: bool = True
    port_scan_ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 8443, 22, 21, 25])
    whois_enabled: bool = True
    asn_lookup_enabled: bool = True
    geoip_enabled: bool = True
    
    # API settings
    user_agent: str = "QuShield/1.0 (PQC Scanner)"
    
    def __post_init__(self):
        """Load overrides from environment variables."""
        for field_name in self.__dataclass_fields__:
            env_var = f"QUSHIELD_{field_name.upper()}"
            if env_var in os.environ:
                value = os.environ[env_var]
                field_type = type(getattr(self, field_name))
                
                # Convert string to appropriate type
                if field_type == bool:
                    setattr(self, field_name, value.lower() in ("true", "1", "yes"))
                elif field_type == int:
                    setattr(self, field_name, int(value))
                elif field_type == list:
                    setattr(self, field_name, value.split(","))
                else:
                    setattr(self, field_name, value)
    
    def ensure_directories(self):
        """Create output and log directories if they don't exist."""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)


# Global configuration instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get or create the global configuration instance."""
    global _config
    if _config is None:
        _config = Config()
    return _config


def set_config(config: Config):
    """Set the global configuration instance."""
    global _config
    _config = config
