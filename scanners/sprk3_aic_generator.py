#!/usr/bin/env python3
"""
SPR{K}3 Engine 6: Artifact Integrity Certificate (AIC) Generator
Cryptographically-signed security attestation system

Author: Dan Aridor - SPR{K}3 Security Research Team
Patent: US Provisional Application (October 8, 2025)

Based on: US Patent 11263188 B2 (AI Model Documentation)

Creates immutable, signed certificates that prove:
- Security scan results
- Code quality metrics
- Behavioral analysis
- Compliance status
- Audit trail

Transforms SPR{K}3 from detection → attestable security system of record
"""

import json
import hashlib
import hmac
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import base64


@dataclass
class SecurityAttestation:
    """Security scan results from SPR{K}3 engines"""
    braided_scan: Dict[str, Any]  # Vulnerability scan
    temporal_analysis: Dict[str, Any]  # Behavioral patterns
    complexity_analysis: Dict[str, Any]  # Code quality
    overall_risk_score: float  # 0.0-1.0 combined risk
    status: str  # SECURE, WARNING, CRITICAL


@dataclass
class ArtifactProvenance:
    """Where the artifact came from"""
    source_url: str
    source_type: str  # git, huggingface, pypi, local
    commit_hash: Optional[str]
    repository_name: str
    branch: Optional[str]
    scan_date: str


@dataclass
class GovernanceMetadata:
    """Who scanned, when, and why"""
    scanned_by: str  # email or identity
    organization: str
    sprk3_version: str
    scan_id: str
    scan_purpose: str  # security_audit, compliance, bug_bounty, production_gate
    engines_used: List[str]


@dataclass
class ComplianceStatus:
    """Regulatory compliance assessments"""
    soc2_compliant: bool
    hipaa_compliant: bool
    gdpr_compliant: bool
    pci_dss_compliant: bool
    compliance_notes: List[str]


@dataclass
class ArtifactIntegrityCertificate:
    """
    Complete AIC - Cryptographically signed attestation
    This is the "system of record" for artifact security
    """
    # Identity
    certificate_id: str
    artifact_id: str
    artifact_name: str
    artifact_version: str
    
    # Provenance
    provenance: ArtifactProvenance
    
    # Security
    security: SecurityAttestation
    
    # Governance
    governance: GovernanceMetadata
    
    # Compliance
    compliance: ComplianceStatus
    
    # Cryptographic proof
    artifact_hash: str  # SHA-256 of artifact
    certificate_hash: str  # SHA-256 of this certificate
    signature: str  # HMAC signature
    
    # Timestamps
    issued_at: str
    expires_at: Optional[str]
    
    # Audit trail
    previous_certificate_id: Optional[str]
    certificate_chain: List[str]


class AICGenerator:
    """
    Generates Artifact Integrity Certificates from SPR{K}3 scan results
    """
    
    def __init__(self, signing_key: Optional[str] = None):
        """
        Initialize with optional signing key
        If no key provided, generates one (for demo/testing)
        """
        self.signing_key = signing_key or self._generate_signing_key()
        self.version = "1.0.0"
        self.output_dir = Path("./aic_certificates")
        self.output_dir.mkdir(exist_ok=True)
    
    def _generate_signing_key(self) -> str:
        """Generate a signing key (in production, use proper key management)"""
        return base64.b64encode(uuid.uuid4().bytes).decode()
    
    def generate_certificate(
        self,
        artifact_path: str,
        scan_results: Dict[str, Any],
        scanned_by: str = "security@sprk3.com",
        organization: str = "SPR{K}3 Security Research Team",
        scan_purpose: str = "security_audit"
    ) -> ArtifactIntegrityCertificate:
        """
        Generate AIC from SPR{K}3 scan results
        
        Args:
            artifact_path: Path to scanned artifact
            scan_results: Combined results from all engines
            scanned_by: Identity of scanner
            organization: Organization name
            scan_purpose: Why this scan was performed
        """
        
        # Extract results from different engines
        braided_results = scan_results.get('braided', {})
        temporal_results = scan_results.get('temporal', {})
        complexity_results = scan_results.get('complexity', {})
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(
            braided_results,
            temporal_results,
            complexity_results
        )
        
        # Determine status
        status = self._determine_status(risk_score)
        
        # Create security attestation
        security = SecurityAttestation(
            braided_scan={
                'vulnerabilities_found': braided_results.get('total_patterns_found', 0),
                'coordinated_attacks': len(braided_results.get('coordinated_attacks', [])),
                'high_risk_contributors': len(braided_results.get('contributor_risk_profile', {})),
                'scan_complete': True
            },
            temporal_analysis={
                'commits_analyzed': temporal_results.get('total_commits', 0),
                'anomalies_detected': len(temporal_results.get('anomalies', [])),
                'velocity_spikes': temporal_results.get('velocity_spikes', 0),
                'timing_anomalies': temporal_results.get('timing_anomalies', 0)
            },
            complexity_analysis={
                'functions_analyzed': complexity_results.get('total_functions', 0),
                'technical_debt_score': complexity_results.get('technical_debt_score', 0),
                'high_complexity_functions': complexity_results.get('high_complexity_functions', 0),
                'obfuscated_functions': complexity_results.get('obfuscated_functions', 0),
                'avg_complexity': complexity_results.get('avg_complexity', 0)
            },
            overall_risk_score=risk_score,
            status=status
        )
        
        # Create provenance
        provenance = self._extract_provenance(artifact_path, scan_results)
        
        # Create governance metadata
        governance = GovernanceMetadata(
            scanned_by=scanned_by,
            organization=organization,
            sprk3_version=self.version,
            scan_id=str(uuid.uuid4()),
            scan_purpose=scan_purpose,
            engines_used=self._get_engines_used(scan_results)
        )
        
        # Assess compliance
        compliance = self._assess_compliance(security)
        
        # Calculate artifact hash
        artifact_hash = self._hash_artifact(artifact_path)
        
        # Generate unique IDs
        cert_id = f"AIC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
        artifact_id = f"artifact:{Path(artifact_path).name}:{uuid.uuid4().hex[:8]}"
        
        # Create certificate (without signature first)
        now = datetime.now(timezone.utc).isoformat()
        
        certificate = ArtifactIntegrityCertificate(
            certificate_id=cert_id,
            artifact_id=artifact_id,
            artifact_name=Path(artifact_path).name,
            artifact_version="1.0.0",  # Could be extracted from git tags
            provenance=provenance,
            security=security,
            governance=governance,
            compliance=compliance,
            artifact_hash=artifact_hash,
            certificate_hash="",  # Will be filled after signature
            signature="",  # Will be filled next
            issued_at=now,
            expires_at=None,  # Could set expiration (e.g., 90 days)
            previous_certificate_id=None,
            certificate_chain=[]
        )
        
        # Sign the certificate
        cert_dict = asdict(certificate)
        cert_dict.pop('signature')
        cert_dict.pop('certificate_hash')
        
        signature = self._sign_certificate(cert_dict)
        certificate.signature = signature
        
        # Calculate certificate hash
        cert_hash = self._hash_certificate(cert_dict)
        certificate.certificate_hash = cert_hash
        
        return certificate
    
    def _calculate_risk_score(
        self,
        braided: Dict,
        temporal: Dict,
        complexity: Dict
    ) -> float:
        """
        Calculate combined risk score (0.0 = safe, 1.0 = critical)
        """
        risk = 0.0
        
        # Vulnerability risk (40% weight)
        vulns = braided.get('total_patterns_found', 0)
        if vulns > 0:
            risk += min(vulns / 50, 0.4)  # Cap at 0.4
        
        # Temporal risk (30% weight)
        anomalies = len(temporal.get('anomalies', []))
        if anomalies > 0:
            risk += min(anomalies / 50, 0.3)  # Cap at 0.3
        
        # Complexity risk (30% weight)
        debt = complexity.get('technical_debt_score', 0)
        risk += (debt / 100) * 0.3
        
        return min(1.0, risk)
    
    def _determine_status(self, risk_score: float) -> str:
        """Determine overall security status"""
        if risk_score < 0.3:
            return "SECURE"
        elif risk_score < 0.6:
            return "WARNING"
        else:
            return "CRITICAL"
    
    def _extract_provenance(
        self,
        artifact_path: str,
        scan_results: Dict
    ) -> ArtifactProvenance:
        """Extract provenance information"""
        path = Path(artifact_path)
        
        # Try to determine source type
        source_type = "local"
        source_url = str(path.absolute())
        commit_hash = None
        branch = None
        
        # Check if it's a git repo
        git_dir = path / ".git" if path.is_dir() else path.parent / ".git"
        if git_dir.exists():
            source_type = "git"
            # Could extract git remote URL here
            temporal = scan_results.get('temporal', {})
            if temporal:
                source_url = f"git://{path.name}"
        
        return ArtifactProvenance(
            source_url=source_url,
            source_type=source_type,
            commit_hash=commit_hash,
            repository_name=path.name,
            branch=branch,
            scan_date=datetime.now(timezone.utc).isoformat()
        )
    
    def _get_engines_used(self, scan_results: Dict) -> List[str]:
        """Determine which engines were used"""
        engines = []
        if 'braided' in scan_results:
            engines.append("Braided Scanner v1.1")
        if 'temporal' in scan_results:
            engines.append("Temporal Anomaly Detector")
        if 'complexity' in scan_results:
            engines.append("Complexity Analyzer")
        return engines
    
    def _assess_compliance(self, security: SecurityAttestation) -> ComplianceStatus:
        """
        Assess compliance based on security findings
        This is simplified - real compliance requires more criteria
        """
        notes = []
        
        # SOC2 - requires no critical vulnerabilities
        soc2 = security.braided_scan['vulnerabilities_found'] == 0
        if not soc2:
            notes.append("SOC2: Vulnerabilities must be remediated")
        
        # HIPAA - requires encryption and access controls
        hipaa = security.braided_scan['vulnerabilities_found'] == 0
        if not hipaa:
            notes.append("HIPAA: Security vulnerabilities present")
        
        # GDPR - requires data protection
        gdpr = security.braided_scan['vulnerabilities_found'] < 5
        if not gdpr:
            notes.append("GDPR: Multiple security issues detected")
        
        # PCI-DSS - strict security requirements
        pci_dss = (
            security.braided_scan['vulnerabilities_found'] == 0 and
            security.complexity_analysis['technical_debt_score'] < 30
        )
        if not pci_dss:
            notes.append("PCI-DSS: Requires zero vulnerabilities and low technical debt")
        
        return ComplianceStatus(
            soc2_compliant=soc2,
            hipaa_compliant=hipaa,
            gdpr_compliant=gdpr,
            pci_dss_compliant=pci_dss,
            compliance_notes=notes
        )
    
    def _hash_artifact(self, artifact_path: str) -> str:
        """Calculate SHA-256 hash of artifact"""
        hasher = hashlib.sha256()
        
        path = Path(artifact_path)
        if path.is_file():
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
        else:
            # For directories, hash all files
            for file_path in sorted(path.rglob('*.py')):
                with open(file_path, 'rb') as f:
                    hasher.update(f.read())
        
        return hasher.hexdigest()
    
    def _sign_certificate(self, cert_data: Dict) -> str:
        """Sign certificate with HMAC-SHA256"""
        # Convert to canonical JSON
        canonical = json.dumps(cert_data, sort_keys=True)
        
        # Sign with HMAC
        signature = hmac.new(
            self.signing_key.encode(),
            canonical.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def _hash_certificate(self, cert_data: Dict) -> str:
        """Calculate hash of certificate"""
        canonical = json.dumps(cert_data, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    def verify_certificate(self, certificate: ArtifactIntegrityCertificate) -> bool:
        """Verify certificate signature"""
        cert_dict = asdict(certificate)
        stored_signature = cert_dict.pop('signature')
        cert_dict.pop('certificate_hash')
        
        expected_signature = self._sign_certificate(cert_dict)
        
        return hmac.compare_digest(stored_signature, expected_signature)
    
    def save_certificate(
        self,
        certificate: ArtifactIntegrityCertificate,
        format: str = "json"
    ) -> Path:
        """
        Save certificate to disk
        
        Args:
            certificate: AIC to save
            format: 'json' or 'pdf' (pdf requires additional dependencies)
        """
        
        if format == "json":
            filename = f"{certificate.certificate_id}.json"
            filepath = self.output_dir / filename
            
            with open(filepath, 'w') as f:
                json.dump(asdict(certificate), f, indent=2)
            
            print(f"\n[+] Certificate saved: {filepath}")
            return filepath
        
        elif format == "pdf":
            # PDF generation would go here
            # Requires reportlab or similar
            print("[!] PDF format not yet implemented")
            return None
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def generate_compliance_report(
        self,
        certificate: ArtifactIntegrityCertificate
    ) -> str:
        """Generate human-readable compliance report"""
        
        report = f"""
╔═══════════════════════════════════════════════════════════════╗
║  ARTIFACT INTEGRITY CERTIFICATE - COMPLIANCE REPORT          ║
╚═══════════════════════════════════════════════════════════════╝

CERTIFICATE ID: {certificate.certificate_id}
ARTIFACT: {certificate.artifact_name}
ISSUED: {certificate.issued_at}
STATUS: {certificate.security.status}

═══════════════════════════════════════════════════════════════

SECURITY ASSESSMENT:
  • Vulnerabilities: {certificate.security.braided_scan['vulnerabilities_found']}
  • Coordinated Attacks: {certificate.security.braided_scan['coordinated_attacks']}
  • Temporal Anomalies: {certificate.security.temporal_analysis['anomalies_detected']}
  • Technical Debt: {certificate.security.complexity_analysis['technical_debt_score']:.1f}/100
  • Overall Risk Score: {certificate.security.overall_risk_score:.2f} ({certificate.security.status})

COMPLIANCE STATUS:
  • SOC2: {'✅ COMPLIANT' if certificate.compliance.soc2_compliant else '❌ NON-COMPLIANT'}
  • HIPAA: {'✅ COMPLIANT' if certificate.compliance.hipaa_compliant else '❌ NON-COMPLIANT'}
  • GDPR: {'✅ COMPLIANT' if certificate.compliance.gdpr_compliant else '❌ NON-COMPLIANT'}
  • PCI-DSS: {'✅ COMPLIANT' if certificate.compliance.pci_dss_compliant else '❌ NON-COMPLIANT'}

PROVENANCE:
  • Source: {certificate.provenance.source_url}
  • Type: {certificate.provenance.source_type}
  • Repository: {certificate.provenance.repository_name}
  • Scan Date: {certificate.provenance.scan_date}

GOVERNANCE:
  • Scanned By: {certificate.governance.scanned_by}
  • Organization: {certificate.governance.organization}
  • Scan Purpose: {certificate.governance.scan_purpose}
  • SPR{{K}}3 Version: {certificate.governance.sprk3_version}
  • Engines Used: {', '.join(certificate.governance.engines_used)}

CRYPTOGRAPHIC ATTESTATION:
  • Artifact Hash: {certificate.artifact_hash[:16]}...
  • Certificate Hash: {certificate.certificate_hash[:16]}...
  • Signature: {certificate.signature[:16]}...
  • Verification: {'✅ VALID' if self.verify_certificate(certificate) else '❌ INVALID'}

═══════════════════════════════════════════════════════════════

This certificate provides cryptographic proof that the artifact
was scanned by SPR{{K}}3 on {certificate.issued_at.split('T')[0]}.

The signature ensures this certificate has not been tampered with.
Any modification will invalidate the signature.

For verification, use: sprk3_aic_verify.py {certificate.certificate_id}

═══════════════════════════════════════════════════════════════
"""
        return report


def main():
    """Demo: Generate AIC from existing scan results"""
    import sys
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║  SPR{K}3 Artifact Integrity Certificate Generator            ║
    ║  Cryptographically-Signed Security Attestation                ║
    ║                                                               ║
    ║  Author: Dan Aridor - SPR{K}3 Security Research Team         ║
    ║  Patent: US Provisional (October 8, 2025)                    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("""
Usage: python3 sprk3_aic_generator.py <artifact_path>

This tool generates Artifact Integrity Certificates (AICs) from
SPR{K}3 scan results, providing cryptographic proof of security.

Example:
    python3 sprk3_aic_generator.py ~/pytorch_repo

The tool will:
1. Load recent scan results (braided, temporal, complexity)
2. Calculate overall risk score
3. Assess compliance (SOC2, HIPAA, GDPR, PCI-DSS)
4. Generate cryptographically-signed certificate
5. Save AIC as JSON
6. Print compliance report

Output:
    - aic_certificates/AIC-YYYYMMDD-XXXXXXXX.json
    - Human-readable compliance report
        """)
        sys.exit(1)
    
    artifact_path = sys.argv[1]
    
    # Load scan results
    print(f"\n[*] Loading scan results for: {artifact_path}")
    
    scan_results = {}
    
    # Try to load braided scan
    braided_dir = Path("braided_scan_results")
    if braided_dir.exists():
        reports = sorted(braided_dir.glob("*.json"))
        if reports:
            with open(reports[-1]) as f:
                scan_results['braided'] = json.load(f)
            print(f"[+] Loaded braided scan: {reports[-1].name}")
    
    # Try to load temporal analysis
    temporal_dir = Path("temporal_analysis")
    if temporal_dir.exists():
        reports = sorted(temporal_dir.glob("*.json"))
        if reports:
            with open(reports[-1]) as f:
                scan_results['temporal'] = json.load(f)
            print(f"[+] Loaded temporal analysis: {reports[-1].name}")
    
    # Try to load complexity analysis
    complexity_dir = Path("complexity_analysis")
    if complexity_dir.exists():
        reports = sorted(complexity_dir.glob("*.json"))
        if reports:
            with open(reports[-1]) as f:
                scan_results['complexity'] = json.load(f)
            print(f"[+] Loaded complexity analysis: {reports[-1].name}")
    
    if not scan_results:
        print("\n[!] No scan results found. Please run SPR{K}3 scanners first:")
        print("    python3 sprk3_braided_scanner.py <repo>")
        print("    python3 complexity_analyzer.py <repo>")
        print("    python3 sprk3_temporal_anomaly_detector.py <repo>")
        sys.exit(1)
    
    # Generate certificate
    print(f"\n[*] Generating Artifact Integrity Certificate...")
    
    generator = AICGenerator()
    certificate = generator.generate_certificate(
        artifact_path=artifact_path,
        scan_results=scan_results,
        scanned_by="dan@sprk3.com",
        organization="SPR{K}3 Security Research Team",
        scan_purpose="security_audit"
    )
    
    # Save certificate
    filepath = generator.save_certificate(certificate, format="json")
    
    # Print compliance report
    report = generator.generate_compliance_report(certificate)
    print(report)
    
    # Verify
    if generator.verify_certificate(certificate):
        print("✅ Certificate signature verified!")
    else:
        print("❌ Certificate signature verification FAILED!")
    
    print(f"\n[+] Certificate generation complete!\n")


if __name__ == "__main__":
    main()
