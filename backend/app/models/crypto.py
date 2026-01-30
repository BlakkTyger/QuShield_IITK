"""Crypto Security Model"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Boolean
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import relationship
from app.database import Base


class CryptoSecurity(Base):
    """Cryptographic security details model."""
    
    __tablename__ = "crypto_security"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id = Column(String(36), ForeignKey("assets.id"), nullable=False, index=True)
    
    # TLS info
    tls_version = Column(String(20))  # TLS 1.0, 1.1, 1.2, 1.3
    supported_tls_versions = Column(JSON)  # List of all supported versions
    
    # Cipher suite
    cipher_suite = Column(String(255))
    cipher_suites = Column(JSON)  # List of all supported cipher suites
    
    # Key exchange
    key_exchange_algorithm = Column(String(100))
    key_exchange_algorithms = Column(JSON)
    
    # Encryption
    encryption_algorithm = Column(String(100))
    key_length = Column(Integer)
    
    # MAC
    mac_algorithm = Column(String(100))
    
    # Security features
    is_pfs_enabled = Column(Boolean, default=False)  # Perfect Forward Secrecy
    supports_tls13 = Column(Boolean, default=False)
    supports_hsts = Column(Boolean, default=False)
    
    # Vulnerabilities
    vulnerable_to_heartbleed = Column(Boolean, default=False)
    vulnerable_to_poodle = Column(Boolean, default=False)
    supports_fallback_scsv = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    asset = relationship("Asset", back_populates="crypto_security")
