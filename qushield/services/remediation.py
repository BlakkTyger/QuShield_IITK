"""
Remediation Advisor

Generates per-asset configuration patches and migration plans for transitioning
from quantum-vulnerable cryptography to post-quantum cryptography (PQC).

Features:
- Template library keyed by (server_type × current_algorithm → target_algorithm)
- Nginx/Apache/OpenSSL configuration snippets
- Effort estimation in hours
- Migration timeline recommendations
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import json

from qushield.utils.logging import get_logger, timed
from qushield.core.classifier import PQCClassifier, QuantumSafety, AlgorithmInfo

logger = get_logger("remediation")


class ServerType(str, Enum):
    """Supported server types for remediation"""
    NGINX = "nginx"
    APACHE = "apache"
    OPENSSL = "openssl"
    HAPROXY = "haproxy"
    IIS = "iis"
    TOMCAT = "tomcat"
    NODE = "nodejs"
    PYTHON = "python"
    JAVA = "java"
    GENERIC = "generic"


class MigrationPhase(str, Enum):
    """Migration phases"""
    ASSESSMENT = "assessment"
    PREPARATION = "preparation"
    HYBRID_DEPLOYMENT = "hybrid_deployment"
    TESTING = "testing"
    FULL_PQC = "full_pqc"
    MONITORING = "monitoring"


@dataclass
class ConfigPatch:
    """Configuration patch for a specific server"""
    server_type: ServerType
    file_path: str
    description: str
    current_config: str
    recommended_config: str
    notes: List[str] = field(default_factory=list)


@dataclass
class MigrationStep:
    """A single step in the migration plan"""
    phase: MigrationPhase
    step_number: int
    title: str
    description: str
    effort_hours: float
    commands: List[str] = field(default_factory=list)
    verification: str = ""
    rollback: str = ""


@dataclass
class RemediationPlan:
    """Complete remediation plan for an asset"""
    asset_fqdn: str
    current_algorithms: List[str]
    target_algorithms: List[str]
    risk_level: str
    total_effort_hours: float
    estimated_timeline_days: int
    config_patches: List[ConfigPatch] = field(default_factory=list)
    migration_steps: List[MigrationStep] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_fqdn": self.asset_fqdn,
            "current_algorithms": self.current_algorithms,
            "target_algorithms": self.target_algorithms,
            "risk_level": self.risk_level,
            "total_effort_hours": self.total_effort_hours,
            "estimated_timeline_days": self.estimated_timeline_days,
            "prerequisites": self.prerequisites,
            "warnings": self.warnings,
            "config_patches": [
                {
                    "server_type": p.server_type.value,
                    "file_path": p.file_path,
                    "description": p.description,
                    "current_config": p.current_config,
                    "recommended_config": p.recommended_config,
                    "notes": p.notes,
                }
                for p in self.config_patches
            ],
            "migration_steps": [
                {
                    "phase": s.phase.value,
                    "step_number": s.step_number,
                    "title": s.title,
                    "description": s.description,
                    "effort_hours": s.effort_hours,
                    "commands": s.commands,
                    "verification": s.verification,
                    "rollback": s.rollback,
                }
                for s in self.migration_steps
            ],
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ============================================================================
# Configuration Templates
# ============================================================================

NGINX_TLS_TEMPLATES = {
    "current_vulnerable": '''
# Current TLS Configuration (Quantum Vulnerable)
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers on;
ssl_ecdh_curve secp384r1;
''',
    "hybrid_pqc": '''
# Hybrid PQC Configuration (Transitional)
# Requires OpenSSL 3.2+ with oqs-provider
ssl_protocols TLSv1.3;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;
ssl_prefer_server_ciphers off;

# Enable hybrid key exchange
ssl_conf_command Groups X25519MLKEM768:X25519:secp384r1;
''',
    "full_pqc": '''
# Full PQC Configuration (Post-2030)
# Requires OpenSSL 3.4+ or LibOQS
ssl_protocols TLSv1.3;
ssl_ciphers TLS_AES_256_GCM_SHA384;
ssl_ecdh_curve ML-KEM-768;
ssl_prefer_server_ciphers off;

# PQC-only key exchange
ssl_conf_command Groups mlkem768:mlkem1024;
ssl_conf_command SignatureAlgorithms mldsa65:mldsa87;
''',
}

APACHE_TLS_TEMPLATES = {
    "current_vulnerable": '''
# Current TLS Configuration (Quantum Vulnerable)
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder on
SSLOpenSSLConfCmd ECDHParameters secp384r1
''',
    "hybrid_pqc": '''
# Hybrid PQC Configuration (Transitional)
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 -TLSv1.2
SSLCipherSuite TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
SSLHonorCipherOrder off
SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:secp384r1
''',
    "full_pqc": '''
# Full PQC Configuration (Post-2030)
SSLProtocol TLSv1.3
SSLCipherSuite TLS_AES_256_GCM_SHA384
SSLOpenSSLConfCmd Groups mlkem768:mlkem1024
SSLOpenSSLConfCmd SignatureAlgorithms mldsa65:mldsa87
''',
}

OPENSSL_TEMPLATES = {
    "hybrid_pqc": '''
# OpenSSL 3.2+ configuration for hybrid PQC
# /etc/ssl/openssl.cnf additions

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = /usr/lib/ossl-modules/oqsprovider.so

[system_default_sect]
Groups = X25519MLKEM768:X25519:secp384r1
SignatureAlgorithms = mldsa65:ecdsa_secp384r1_sha384
''',
    "full_pqc": '''
# OpenSSL configuration for full PQC
[system_default_sect]
Groups = mlkem768:mlkem1024
SignatureAlgorithms = mldsa65:mldsa87:slhdsa128s
MinProtocol = TLSv1.3
''',
}

JAVA_TEMPLATES = {
    "hybrid_pqc": '''
// Java application.properties or system properties
# Enable Bouncy Castle PQC provider
java.security.providers.11=org.bouncycastle.jce.provider.BouncyCastleProvider
java.security.providers.12=org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider

# TLS configuration
jdk.tls.client.protocols=TLSv1.3
jdk.tls.namedGroups=X25519MLKEM768,X25519,secp384r1
''',
}

NODE_TEMPLATES = {
    "hybrid_pqc": '''
// Node.js TLS configuration with PQC support
const tls = require('tls');
const https = require('https');

const options = {
  // Requires Node.js 22+ with OpenSSL 3.2+
  ecdhCurve: 'X25519MLKEM768:X25519:secp384r1',
  ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
  minVersion: 'TLSv1.3',
  maxVersion: 'TLSv1.3',
};

const server = https.createServer(options, (req, res) => {
  // Application code
});
''',
}

PYTHON_TEMPLATES = {
    "hybrid_pqc": '''
# Python SSL context with PQC support
# Requires Python 3.12+ with OpenSSL 3.2+
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3

# Set PQC cipher suites (requires patched ssl module or liboqs bindings)
context.set_ciphers('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256')

# For hybrid key exchange, use liboqs-python
# pip install liboqs-python
from oqs import KeyEncapsulation
kem = KeyEncapsulation("ML-KEM-768")
''',
}


# ============================================================================
# Effort Estimation Matrix
# ============================================================================

EFFORT_MATRIX = {
    # (current_safety, target_safety): base_hours
    (QuantumSafety.CRITICAL, QuantumSafety.FULLY_SAFE): 40,
    (QuantumSafety.CRITICAL, QuantumSafety.HYBRID): 24,
    (QuantumSafety.VULNERABLE, QuantumSafety.FULLY_SAFE): 32,
    (QuantumSafety.VULNERABLE, QuantumSafety.HYBRID): 16,
    (QuantumSafety.HYBRID, QuantumSafety.FULLY_SAFE): 8,
}

SERVER_EFFORT_MULTIPLIER = {
    ServerType.NGINX: 1.0,
    ServerType.APACHE: 1.1,
    ServerType.OPENSSL: 0.8,
    ServerType.HAPROXY: 1.2,
    ServerType.IIS: 1.5,
    ServerType.TOMCAT: 1.3,
    ServerType.NODE: 1.0,
    ServerType.PYTHON: 0.9,
    ServerType.JAVA: 1.4,
    ServerType.GENERIC: 1.2,
}


class RemediationAdvisor:
    """
    Generates remediation plans and configuration patches for PQC migration.
    
    Features:
    - Per-asset configuration patches
    - Migration timeline and steps
    - Effort estimation
    - Server-specific templates
    """
    
    def __init__(self):
        self.classifier = PQCClassifier()
    
    @timed(logger=logger, layer=3)
    def generate_plan(
        self,
        asset_fqdn: str,
        current_algorithms: List[str],
        server_type: ServerType = ServerType.GENERIC,
        target_safety: QuantumSafety = QuantumSafety.HYBRID,
    ) -> RemediationPlan:
        """
        Generate a complete remediation plan for an asset.
        
        Args:
            asset_fqdn: Fully qualified domain name of the asset
            current_algorithms: List of algorithms currently in use
            server_type: Type of server (nginx, apache, etc.)
            target_safety: Target quantum safety level
            
        Returns:
            RemediationPlan with steps, patches, and estimates
        """
        logger.info(f"Generating remediation plan for {asset_fqdn}", extra={
            "layer": 3,
            "target": asset_fqdn,
            "data": {
                "current_algorithms": current_algorithms,
                "server_type": server_type.value,
                "target_safety": target_safety.value,
            }
        })
        
        # Analyze current state
        current_safety = self.classifier.get_effective_safety(current_algorithms)
        target_algorithms = self._get_target_algorithms(current_algorithms)
        
        # Calculate effort
        base_effort = EFFORT_MATRIX.get(
            (current_safety, target_safety),
            16  # Default
        )
        multiplier = SERVER_EFFORT_MULTIPLIER.get(server_type, 1.0)
        total_effort = base_effort * multiplier
        
        # Estimate timeline (8 hours per day, 50% allocation)
        timeline_days = int(total_effort / 4) + 7  # Add buffer
        
        # Generate components
        config_patches = self._generate_config_patches(
            server_type, current_algorithms, target_safety
        )
        migration_steps = self._generate_migration_steps(
            asset_fqdn, current_algorithms, target_algorithms, server_type
        )
        prerequisites = self._get_prerequisites(server_type, target_safety)
        warnings = self._get_warnings(current_safety, target_safety)
        
        plan = RemediationPlan(
            asset_fqdn=asset_fqdn,
            current_algorithms=current_algorithms,
            target_algorithms=target_algorithms,
            risk_level=current_safety.value,
            total_effort_hours=total_effort,
            estimated_timeline_days=timeline_days,
            config_patches=config_patches,
            migration_steps=migration_steps,
            prerequisites=prerequisites,
            warnings=warnings,
        )
        
        logger.info(f"Remediation plan generated", extra={
            "layer": 3,
            "target": asset_fqdn,
            "data": {
                "effort_hours": total_effort,
                "timeline_days": timeline_days,
                "steps_count": len(migration_steps),
            }
        })
        
        return plan
    
    def _get_target_algorithms(self, current_algorithms: List[str]) -> List[str]:
        """Determine target algorithms based on current ones"""
        targets = set()
        for algo in current_algorithms:
            info = self.classifier.classify(algo)
            if info.migrate_to:
                targets.add(info.migrate_to)
        return list(targets) or ["ML-KEM-768", "ML-DSA-65"]
    
    def _generate_config_patches(
        self,
        server_type: ServerType,
        current_algorithms: List[str],
        target_safety: QuantumSafety,
    ) -> List[ConfigPatch]:
        """Generate server-specific configuration patches"""
        patches = []
        
        target_key = "hybrid_pqc" if target_safety == QuantumSafety.HYBRID else "full_pqc"
        
        if server_type == ServerType.NGINX:
            patches.append(ConfigPatch(
                server_type=ServerType.NGINX,
                file_path="/etc/nginx/conf.d/ssl.conf",
                description="Nginx TLS configuration for PQC",
                current_config=NGINX_TLS_TEMPLATES["current_vulnerable"],
                recommended_config=NGINX_TLS_TEMPLATES.get(target_key, NGINX_TLS_TEMPLATES["hybrid_pqc"]),
                notes=[
                    "Requires OpenSSL 3.2+ with oqs-provider",
                    "Test thoroughly before production deployment",
                    "Monitor for client compatibility issues",
                ],
            ))
            
        elif server_type == ServerType.APACHE:
            patches.append(ConfigPatch(
                server_type=ServerType.APACHE,
                file_path="/etc/apache2/mods-available/ssl.conf",
                description="Apache TLS configuration for PQC",
                current_config=APACHE_TLS_TEMPLATES["current_vulnerable"],
                recommended_config=APACHE_TLS_TEMPLATES.get(target_key, APACHE_TLS_TEMPLATES["hybrid_pqc"]),
                notes=[
                    "Requires mod_ssl with OpenSSL 3.2+",
                    "Restart Apache after changes: systemctl restart apache2",
                ],
            ))
            
        elif server_type == ServerType.OPENSSL:
            patches.append(ConfigPatch(
                server_type=ServerType.OPENSSL,
                file_path="/etc/ssl/openssl.cnf",
                description="OpenSSL system-wide PQC configuration",
                current_config="# Default OpenSSL configuration",
                recommended_config=OPENSSL_TEMPLATES.get(target_key, OPENSSL_TEMPLATES["hybrid_pqc"]),
                notes=[
                    "Install liboqs and oqs-provider first",
                    "This affects all applications using OpenSSL",
                ],
            ))
            
        elif server_type == ServerType.NODE:
            patches.append(ConfigPatch(
                server_type=ServerType.NODE,
                file_path="server.js or https configuration",
                description="Node.js HTTPS server PQC configuration",
                current_config="// Default TLS options",
                recommended_config=NODE_TEMPLATES.get(target_key, NODE_TEMPLATES["hybrid_pqc"]),
                notes=[
                    "Requires Node.js 22+ with OpenSSL 3.2+",
                    "Update package.json engines field",
                ],
            ))
            
        elif server_type == ServerType.PYTHON:
            patches.append(ConfigPatch(
                server_type=ServerType.PYTHON,
                file_path="ssl_context.py or application config",
                description="Python SSL context PQC configuration",
                current_config="# Default SSL context",
                recommended_config=PYTHON_TEMPLATES.get(target_key, PYTHON_TEMPLATES["hybrid_pqc"]),
                notes=[
                    "Requires Python 3.12+ with OpenSSL 3.2+",
                    "Consider using liboqs-python for full PQC support",
                ],
            ))
            
        elif server_type == ServerType.JAVA:
            patches.append(ConfigPatch(
                server_type=ServerType.JAVA,
                file_path="application.properties or java.security",
                description="Java TLS configuration for PQC",
                current_config="# Default Java TLS settings",
                recommended_config=JAVA_TEMPLATES.get(target_key, JAVA_TEMPLATES["hybrid_pqc"]),
                notes=[
                    "Requires Java 21+ or Bouncy Castle PQC provider",
                    "Add BC dependencies to build file",
                ],
            ))
        
        else:
            # Generic advice
            patches.append(ConfigPatch(
                server_type=ServerType.GENERIC,
                file_path="TLS configuration file",
                description="Generic PQC migration guidance",
                current_config="# Current TLS configuration",
                recommended_config=f"""
# Generic PQC Migration Steps:
# 1. Upgrade to TLS 1.3 only
# 2. Enable hybrid key exchange (X25519+ML-KEM-768)
# 3. Use AES-256-GCM for symmetric encryption
# 4. Plan for ML-DSA certificate migration

# Target algorithms:
# - Key Exchange: ML-KEM-768 (FIPS 203)
# - Signatures: ML-DSA-65 (FIPS 204)
# - Symmetric: AES-256-GCM (quantum-resistant with doubled key)
""",
                notes=[
                    "Consult vendor documentation for specific configuration",
                    "Test compatibility with all clients before deployment",
                ],
            ))
        
        return patches
    
    def _generate_migration_steps(
        self,
        asset_fqdn: str,
        current_algorithms: List[str],
        target_algorithms: List[str],
        server_type: ServerType,
    ) -> List[MigrationStep]:
        """Generate step-by-step migration plan"""
        steps = []
        step_num = 0
        
        # Phase 1: Assessment
        step_num += 1
        steps.append(MigrationStep(
            phase=MigrationPhase.ASSESSMENT,
            step_number=step_num,
            title="Inventory Current Cryptographic Assets",
            description=f"Document all cryptographic configurations for {asset_fqdn}",
            effort_hours=2,
            commands=[
                f"# Run QuShield scan",
                f"python cli.py scan {asset_fqdn}",
                f"python cli.py classify RSA ECDHE",
            ],
            verification="Review generated CBOM report",
        ))
        
        step_num += 1
        steps.append(MigrationStep(
            phase=MigrationPhase.ASSESSMENT,
            step_number=step_num,
            title="Identify Client Compatibility Requirements",
            description="Assess client support for hybrid and PQC algorithms",
            effort_hours=4,
            commands=[
                "# Check browser/client support",
                "# Chrome 124+: X25519Kyber768",
                "# Firefox 128+: X25519MLKEM768",
            ],
            verification="Document minimum supported client versions",
        ))
        
        # Phase 2: Preparation
        step_num += 1
        steps.append(MigrationStep(
            phase=MigrationPhase.PREPARATION,
            step_number=step_num,
            title="Upgrade OpenSSL/Crypto Libraries",
            description="Install OpenSSL 3.2+ with OQS provider",
            effort_hours=4,
            commands=[
                "# Ubuntu/Debian",
                "sudo apt update && sudo apt install -y openssl libssl-dev",
                "",
                "# Install liboqs",
                "git clone https://github.com/open-quantum-safe/liboqs.git",
                "cd liboqs && mkdir build && cd build",
                "cmake -DBUILD_SHARED_LIBS=ON ..",
                "make -j && sudo make install",
                "",
                "# Install oqs-provider",
                "git clone https://github.com/open-quantum-safe/oqs-provider.git",
                "cd oqs-provider && mkdir build && cd build",
                "cmake .. && make && sudo make install",
            ],
            verification="openssl list -providers | grep oqsprovider",
            rollback="sudo apt install openssl=<previous_version>",
        ))
        
        step_num += 1
        steps.append(MigrationStep(
            phase=MigrationPhase.PREPARATION,
            step_number=step_num,
            title="Generate PQC Test Certificates",
            description="Create test certificates with ML-DSA signatures",
            effort_hours=2,
            commands=[
                "# Generate ML-DSA-65 key pair",
                "openssl genpkey -algorithm mldsa65 -out pqc_key.pem",
                "",
                "# Create CSR",
                "openssl req -new -key pqc_key.pem -out pqc.csr \\",
                "  -subj '/CN=test.example.com/O=Test'",
                "",
                "# Self-sign for testing",
                "openssl x509 -req -in pqc.csr -signkey pqc_key.pem \\",
                "  -out pqc_cert.pem -days 365",
            ],
            verification="openssl x509 -in pqc_cert.pem -text | grep 'Public Key Algorithm'",
        ))
        
        # Phase 3: Hybrid Deployment
        step_num += 1
        steps.append(MigrationStep(
            phase=MigrationPhase.HYBRID_DEPLOYMENT,
            step_number=step_num,
            title="Deploy Hybrid Configuration",
            description=f"Update {server_type.value} to support hybrid key exchange",
            effort_hours=4,
            commands=[
                f"# Backup current configuration",
                f"sudo cp /etc/{server_type.value}/ssl.conf /etc/{server_type.value}/ssl.conf.bak",
                f"",
                f"# Apply hybrid configuration",
                f"# See config_patches section for specific changes",
            ],
            verification=f"curl -v https://{asset_fqdn} 2>&1 | grep 'SSL connection'",
            rollback=f"sudo cp /etc/{server_type.value}/ssl.conf.bak /etc/{server_type.value}/ssl.conf",
        ))
        
        # Phase 4: Testing
        step_num += 1
        steps.append(MigrationStep(
            phase=MigrationPhase.TESTING,
            step_number=step_num,
            title="Validate Hybrid Deployment",
            description="Test hybrid configuration with various clients",
            effort_hours=8,
            commands=[
                "# Test with OpenSSL s_client",
                f"openssl s_client -connect {asset_fqdn}:443 -groups X25519MLKEM768",
                "",
                "# Run QuShield scan to verify",
                f"python cli.py scan {asset_fqdn}",
                "",
                "# Check TLS handshake",
                f"curl -vI https://{asset_fqdn} 2>&1 | grep -i 'ssl\\|tls'",
            ],
            verification="Verify hybrid key exchange is negotiated",
        ))
        
        # Phase 5: Full PQC (future)
        step_num += 1
        steps.append(MigrationStep(
            phase=MigrationPhase.FULL_PQC,
            step_number=step_num,
            title="Plan Full PQC Migration (2030 Target)",
            description="Prepare for pure PQC deployment when ecosystem matures",
            effort_hours=2,
            commands=[
                "# Monitor PQC certificate availability",
                "# Track browser/client PQC support",
                "# Plan certificate authority migration",
            ],
            verification="Document PQC readiness checklist",
        ))
        
        # Phase 6: Monitoring
        step_num += 1
        steps.append(MigrationStep(
            phase=MigrationPhase.MONITORING,
            step_number=step_num,
            title="Implement Ongoing Monitoring",
            description="Set up continuous cryptographic posture monitoring",
            effort_hours=4,
            commands=[
                "# Schedule regular QuShield scans",
                f"0 2 * * * python cli.py scan {asset_fqdn} --output json >> /var/log/qushield/scan.log",
                "",
                "# Set up alerting for quantum-vulnerable algorithms",
            ],
            verification="Verify scheduled scans are running",
        ))
        
        return steps
    
    def _get_prerequisites(
        self,
        server_type: ServerType,
        target_safety: QuantumSafety,
    ) -> List[str]:
        """Get prerequisites for the migration"""
        prereqs = [
            "OpenSSL 3.2+ or LibreSSL with PQC support",
            "liboqs (Open Quantum Safe) library",
            "oqs-provider for OpenSSL",
            "Test environment for validation",
            "Rollback plan documented",
        ]
        
        if server_type == ServerType.NGINX:
            prereqs.append("Nginx 1.25+ compiled with OpenSSL 3.2+")
        elif server_type == ServerType.APACHE:
            prereqs.append("Apache 2.4.52+ with mod_ssl")
        elif server_type == ServerType.JAVA:
            prereqs.append("Bouncy Castle 1.78+ with PQC provider")
        elif server_type == ServerType.NODE:
            prereqs.append("Node.js 22+ with native PQC support")
        elif server_type == ServerType.PYTHON:
            prereqs.append("Python 3.12+ with liboqs-python bindings")
        
        if target_safety == QuantumSafety.FULLY_SAFE:
            prereqs.append("PQC certificates from compatible CA (when available)")
        
        return prereqs
    
    def _get_warnings(
        self,
        current_safety: QuantumSafety,
        target_safety: QuantumSafety,
    ) -> List[str]:
        """Get warnings for the migration"""
        warnings = []
        
        if current_safety == QuantumSafety.CRITICAL:
            warnings.append(
                "CRITICAL: Current algorithms are broken even classically. "
                "Prioritize immediate remediation."
            )
        
        if current_safety == QuantumSafety.VULNERABLE:
            warnings.append(
                "Data encrypted with current algorithms may be at risk of "
                "'Harvest Now, Decrypt Later' attacks."
            )
        
        if target_safety == QuantumSafety.FULLY_SAFE:
            warnings.append(
                "Full PQC deployment is still maturing. Consider hybrid mode "
                "as an intermediate step."
            )
        
        warnings.append(
            "Test thoroughly in staging environment before production deployment."
        )
        warnings.append(
            "Monitor client compatibility - some older clients may not support PQC."
        )
        
        return warnings
    
    def get_quick_fix(
        self,
        algorithm: str,
        server_type: ServerType = ServerType.NGINX,
    ) -> str:
        """Get a quick configuration fix for a specific algorithm"""
        info = self.classifier.classify(algorithm)
        
        if info.safety == QuantumSafety.FULLY_SAFE:
            return f"# {algorithm} is already quantum-safe. No changes needed."
        
        target = info.migrate_to or "ML-KEM-768"
        
        fixes = {
            ServerType.NGINX: f"""
# Quick fix: Migrate {algorithm} to hybrid PQC
# In /etc/nginx/conf.d/ssl.conf:
ssl_ecdh_curve X25519MLKEM768:X25519;
ssl_protocols TLSv1.3;
# Then: sudo nginx -t && sudo systemctl reload nginx
""",
            ServerType.APACHE: f"""
# Quick fix: Migrate {algorithm} to hybrid PQC  
# In /etc/apache2/mods-available/ssl.conf:
SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519
SSLProtocol TLSv1.3
# Then: sudo apachectl configtest && sudo systemctl reload apache2
""",
            ServerType.OPENSSL: f"""
# Quick fix: System-wide hybrid PQC
# In /etc/ssl/openssl.cnf [system_default_sect]:
Groups = X25519MLKEM768:X25519
MinProtocol = TLSv1.3
""",
        }
        
        return fixes.get(server_type, f"""
# Migrate {algorithm} to {target}
# 1. Enable TLS 1.3
# 2. Configure hybrid key exchange (X25519+ML-KEM-768)
# 3. Update to {target} when ecosystem supports it
""")


# Singleton instance
advisor = RemediationAdvisor()


def generate_remediation_plan(
    asset_fqdn: str,
    current_algorithms: List[str],
    server_type: str = "generic",
    target_safety: str = "hybrid",
) -> RemediationPlan:
    """Convenience function to generate a remediation plan"""
    server = ServerType(server_type.lower())
    target = QuantumSafety.HYBRID if target_safety.lower() == "hybrid" else QuantumSafety.FULLY_SAFE
    return advisor.generate_plan(asset_fqdn, current_algorithms, server, target)
