#!/usr/bin/env python3
# Copyright (c) 2025 Dan Aridor
# Licensed under AGPL-3.0 - see LICENSE file
"""
Engine 5: Supply Chain Intelligence - Provenance Kinase
Detects ML supply chain vulnerabilities in codebases
Part of SPR{K}3 5-Engine Architecture
"""

import json
import ast
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum


class SupplyChainSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SupplyChainFinding:
    """Single supply chain vulnerability finding"""
    rule_id: str
    rule_name: str
    severity: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: float
    remediation: str
    cve_mapping: str = ""
    
    def to_dict(self):
        return asdict(self)


class Engine5SupplyChainIntelligence:
    """
    Engine 5: Supply Chain Intelligence
    Detects unsafe model loading, data poisoning entry points, and serialization risks
    
    Rules Implemented:
    - SC-001: Unsafe Pickle/Serialization Loading (CRITICAL)
    - SC-002: Unsigned Model Download (HIGH)
    - SC-003: Custom Unpickler with Code Execution (CRITICAL)
    - SC-005: Unsafe Serialization Formats (HIGH)
    - SC-006: External Dataset Ingestion (HIGH)
    - SC-007: Dynamic Architecture Loading (HIGH)
    """
    
    RULES = {
        'SC-001': {
            'name': 'Unsafe Pickle/Serialization Loading',
            'severity': 'critical',
            'confidence': 0.95,
            'patterns': [
                r'torch\.load\s*\([^)]*\)(?!.*weights_only)',
                r'pickle\.load\s*\(',
                r'joblib\.load\s*\(',
            ]
        },
        'SC-002': {
            'name': 'Unsigned Model Download',
            'severity': 'high',
            'confidence': 0.85,
            'patterns': [
                r'from_pretrained\s*\(["\'](?!(?:facebook|google|openai|meta|microsoft)[/-])',
                r'requests\.\w+.*\.(pth|pt|ckpt|bin)',
                r'urllib.*\.(pth|pt|ckpt|bin)',
            ]
        },
        'SC-003': {
            'name': 'Custom Unpickler with Code Execution',
            'severity': 'critical',
            'confidence': 0.98,
            'patterns': [
                r'def\s+__reduce__\s*\(',
                r'def\s+__getstate__\s*\(',
                r'exec\s*\(',
                r'eval\s*\(',
            ]
        },
        'SC-005': {
            'name': 'Unsafe Serialization Formats',
            'severity': 'high',
            'confidence': 0.80,
            'patterns': [
                r'\.load_model\s*\([^)]*\.h5',
                r'onnx\.load\s*\(',
                r'tensorflow\.keras\.models\.load_model',
            ]
        },
        'SC-006': {
            'name': 'External Dataset Without Validation',
            'severity': 'high',
            'confidence': 0.70,
            'patterns': [
                r'load_dataset\s*\(',
                r'read_csv\s*\(["\']http',
                r'pandas\.read_\w+\s*\(["\']http',
            ]
        },
        'SC-007': {
            'name': 'Dynamic Model Architecture Loading',
            'severity': 'high',
            'confidence': 0.85,
            'patterns': [
                r'trust_remote_code\s*=\s*True',
                r'tensorflow_hub\.load\s*\(',
            ]
        },
    }
    
    REMEDIATION = {
        'SC-001': 'Use torch.load(..., weights_only=True) or convert to .safetensors format',
        'SC-002': 'Add signature verification and pin model versions',
        'SC-003': 'Remove custom unpickler; use safe serialization (JSON, protobuf, safetensors)',
        'SC-005': 'Migrate to .safetensors or ONNX with validation',
        'SC-006': 'Pin dataset versions and verify checksums',
        'SC-007': 'Set trust_remote_code=False (default) and load architectures locally',
    }
    
    CVE_MAPPINGS = {
        'SC-001': 'CVE-2025-23298',
        'SC-002': 'CVE-2025-23298',
        'SC-003': 'CVE-2025-23298',
        'SC-005': 'CVE-2025-23298',
        'SC-006': 'CVE-2025-23298',
        'SC-007': 'CVE-2025-23298',
    }
    
    def __init__(self, repo_path: str = '.', verbose: bool = False):
        self.repo_path = Path(repo_path)
        self.verbose = verbose
        self.findings: List[SupplyChainFinding] = []
    
    def analyze(self) -> Dict:
        """Analyze repository for supply chain vulnerabilities"""
        
        # Scan Python files
        python_files = list(self.repo_path.rglob('*.py'))
        ipynb_files = list(self.repo_path.rglob('*.ipynb'))
        config_files = list(self.repo_path.rglob('setup.py')) + list(self.repo_path.rglob('pyproject.toml'))
        
        all_files = python_files + ipynb_files + config_files
        
        for file_path in all_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                self._scan_file(file_path, content)
            except Exception as e:
                if self.verbose:
                    print(f"Error scanning {file_path}: {e}")
        
        return self._generate_report()
    
    def _scan_file(self, file_path: Path, content: str):
        """Scan single file for supply chain vulnerabilities"""
        lines = content.split('\n')
        
        for rule_id, rule_config in self.RULES.items():
            for pattern in rule_config.get('patterns', []):
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        finding = SupplyChainFinding(
                            rule_id=rule_id,
                            rule_name=rule_config['name'],
                            severity=rule_config['severity'],
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip()[:100],
                            confidence=rule_config['confidence'],
                            remediation=self.REMEDIATION.get(rule_id, ''),
                            cve_mapping=self.CVE_MAPPINGS.get(rule_id, '')
                        )
                        self.findings.append(finding)
    
    def _generate_report(self) -> Dict:
        """Generate supply chain analysis report"""
        
        # Group by severity
        critical = [f for f in self.findings if f.severity == 'critical']
        high = [f for f in self.findings if f.severity == 'high']
        medium = [f for f in self.findings if f.severity == 'medium']
        low = [f for f in self.findings if f.severity == 'low']
        
        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score()
        
        return {
            'engine': 'Engine 5: Supply Chain Intelligence',
            'version': '1.0.0',
            'repository': str(self.repo_path),
            'total_findings': len(self.findings),
            'by_severity': {
                'critical': len(critical),
                'high': len(high),
                'medium': len(medium),
                'low': len(low),
            },
            'risk_score': risk_score,  # 0-100
            'recommendations': self._generate_recommendations(),
            'findings': [f.to_dict() for f in self.findings],
            'cves_detected': list(set(f.cve_mapping for f in self.findings if f.cve_mapping))
        }
    
    def _calculate_risk_score(self) -> float:
        """Calculate overall supply chain risk score (0-100)"""
        if not self.findings:
            return 0.0
        
        severity_weights = {
            'critical': 40,
            'high': 20,
            'medium': 10,
            'low': 5,
        }
        
        total = sum(
            severity_weights.get(f.severity, 0) * f.confidence
            for f in self.findings
        )
        
        return min(100.0, total)
    
    def _generate_recommendations(self) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        rules_with_findings = set(f.rule_id for f in self.findings)
        
        for rule_id in sorted(rules_with_findings):
            if rule_id in self.REMEDIATION:
                recommendations.append(
                    f"{rule_id}: {self.REMEDIATION[rule_id]}"
                )
        
        return recommendations


def estimate_bounty_impact(report: Dict) -> Dict[str, int]:
    """Estimate potential bounty impact for found vulnerabilities"""
    
    severity_bounties = {
        'critical': (5000, 20000),
        'high': (2000, 10000),
        'medium': (500, 2000),
        'low': (100, 500),
    }
    
    total_min = 0
    total_max = 0
    
    for finding in report.get('findings', []):
        severity = finding['severity']
        confidence = finding['confidence']
        
        min_bounty, max_bounty = severity_bounties.get(severity, (0, 0))
        adjustment = confidence * 1.2
        
        total_min += int(min_bounty * adjustment)
        total_max += int(max_bounty * adjustment)
    
    return {
        'estimated_min': total_min,
        'estimated_max': total_max,
        'average_per_finding': int((total_min + total_max) / 2 / max(len(report.get('findings', [])), 1))
    }


if __name__ == '__main__':
    import sys
    
    repo_path = sys.argv[1] if len(sys.argv) > 1 else '.'
    
    engine = Engine5SupplyChainIntelligence(repo_path, verbose=True)
    report = engine.analyze()
    bounty = estimate_bounty_impact(report)
    
    print(f"\n{'='*70}")
    print(f"Engine 5: Supply Chain Intelligence - Analysis Report")
    print(f"{'='*70}")
    print(f"Repository: {report['repository']}")
    print(f"Total Findings: {report['total_findings']}")
    print(f"  - Critical: {report['by_severity']['critical']}")
    print(f"  - High: {report['by_severity']['high']}")
    print(f"Supply Chain Risk Score: {report['risk_score']:.1f}/100")
    print(f"Estimated Bounty Impact: ${bounty['estimated_min']:,} - ${bounty['estimated_max']:,}")
    print(f"{'='*70}\n")
    
    # Save report
    output_file = Path(repo_path) / 'engine5_supply_chain_report.json'
    with open(output_file, 'w') as f:
        json.dump({
            **report,
            'bounty_impact': bounty
        }, f, indent=2)
    
    print(f"Report saved to: {output_file}\n")
