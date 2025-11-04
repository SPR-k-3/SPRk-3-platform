#!/usr/bin/env python3
# Copyright (c) 2025 Dan Aridor
# Licensed under AGPL-3.0 - see LICENSE file
"""
Engine 5: Supply Chain Intelligence - Provenance Kinase (v2.0 - FIXED)
Detects ML supply chain vulnerabilities in codebases
Part of SPR{K}3 5-Engine Architecture

v2.0 Improvements:
- String/comment filtering to eliminate false positives
- Safe variant recognition (weights_only=True, .safetensors)
- Test file exclusion (tests/, examples/, *_demo.py)
- ORM method whitelist (SQLAlchemy, Django, etc.)
- Realistic bounty estimation
- Better confidence scoring based on context
"""

import json
import ast
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
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
    false_positive_risk: str = "low"  # NEW: confidence that this is real
    
    def to_dict(self):
        return asdict(self)


class Engine5SupplyChainIntelligence:
    """
    Engine 5: Supply Chain Intelligence (v2.0)
    Detects unsafe model loading, data poisoning entry points, and serialization risks
    
    Rules Implemented:
    - SC-001: Unsafe Pickle/Serialization Loading (CRITICAL)
    - SC-002: Unsigned Model Download (HIGH)
    - SC-003: Custom Unpickler with Code Execution (CRITICAL)
    - SC-005: Unsafe Serialization Formats (HIGH)
    - SC-006: External Dataset Ingestion (HIGH)
    - SC-007: Dynamic Architecture Loading (HIGH)
    """
    
    # Skip these directories and file patterns to avoid test/example code
    SKIP_DIRS = {
        'tests/', 'test_', 'examples/', 'demo', 
        '__pycache__', '.git', '.venv', 'venv',
        'openai-python', 'agentland_defense'  # Vendor code
    }
    
    SKIP_FILES = {
        'create_exploit.py',
        'suspicious_code_demo.py',
        'test_sprk3.py',
        'conftest.py',
        'setup.py',
        'sprk3_false_positive_filter.py',  # Meta - scanner testing file
        'bounty_hunter.py',  # Demo scanner
        'improved_bounty_hunter.py',  # Demo scanner
    }
    
    # ORM methods that aren't dangerous despite looking like exec/eval
    ORM_SAFE_METHODS = {
        'session.exec',  # SQLAlchemy
        'session.query.execute',
        'db.session.exec',
        'objects.filter',  # Django
        'objects.exclude',
        'queryset.filter',
        'execute_sql',  # Generic
        'execute_query',
        'run_query',
    }
    
    RULES = {
        'SC-001': {
            'name': 'Unsafe Pickle/Serialization Loading',
            'severity': 'critical',
            'confidence': 0.95,
            'patterns': [
                (r'torch\.load\s*\([^)]*\)', 'torch'),
                (r'pickle\.load\s*\(', 'pickle'),
                (r'joblib\.load\s*\(', 'joblib'),
                (r'\.load_model\s*\(', 'keras'),
            ]
        },
        'SC-002': {
            'name': 'Unsigned Model Download',
            'severity': 'high',
            'confidence': 0.80,
            'patterns': [
                (r'from_pretrained\s*\(["\'](?!(?:facebook|google|openai|meta|microsoft)[/-])', 'huggingface'),
                (r'requests\.\w+.*\.(pth|pt|ckpt|bin)', 'requests'),
                (r'urllib.*\.(pth|pt|ckpt|bin)', 'urllib'),
            ]
        },
        'SC-003': {
            'name': 'Custom Unpickler with Code Execution',
            'severity': 'critical',
            'confidence': 0.95,
            'patterns': [
                (r'def\s+__reduce__\s*\(', 'reduce'),
                (r'def\s+__getstate__\s*\(', 'getstate'),
                (r'\bexec\s*\(', 'exec'),
                (r'\beval\s*\(', 'eval'),
            ]
        },
        'SC-005': {
            'name': 'Unsafe Serialization Formats',
            'severity': 'high',
            'confidence': 0.80,
            'patterns': [
                (r'\.load_model\s*\([^)]*\.h5', 'h5'),
                (r'onnx\.load\s*\(', 'onnx'),
                (r'tensorflow\.keras\.models\.load_model', 'keras'),
            ]
        },
        'SC-006': {
            'name': 'External Dataset Without Validation',
            'severity': 'high',
            'confidence': 0.70,
            'patterns': [
                (r'load_dataset\s*\(', 'huggingface_dataset'),
                (r'read_csv\s*\(["\']http', 'pandas_http'),
                (r'pandas\.read_\w+\s*\(["\']http', 'pandas_http'),
            ]
        },
        'SC-007': {
            'name': 'Dynamic Model Architecture Loading',
            'severity': 'high',
            'confidence': 0.85,
            'patterns': [
                (r'trust_remote_code\s*=\s*True', 'trust_remote'),
                (r'tensorflow_hub\.load\s*\(', 'tf_hub'),
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
            # FIX #3: Skip test/example files
            if self._should_skip_file(file_path):
                if self.verbose:
                    print(f"[SKIP] {file_path}")
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                self._scan_file(file_path, content)
            except Exception as e:
                if self.verbose:
                    print(f"Error scanning {file_path}: {e}")
        
        return self._generate_report()
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped (test, example, demo code)"""
        file_str = str(file_path)
        
        # Skip entire directories
        for skip_dir in self.SKIP_DIRS:
            if skip_dir in file_str:
                return True
        
        # Skip specific files
        if file_path.name in self.SKIP_FILES:
            return True
        
        # Skip test files
        if file_path.name.startswith('test_') or file_path.name.endswith('_test.py'):
            return True
        
        # Skip demo/example files
        if '_demo' in file_str or '_example' in file_str or 'conftest' in file_str:
            return True
        
        return False
    
    def _is_string_or_comment(self, line: str, pattern: str) -> bool:
        """
        FIX #1: Check if the pattern match is inside a string or comment
        Returns True if the pattern is NOT in executable code
        """
        # Remove comments first
        if '#' in line:
            code_part = line.split('#')[0]
        else:
            code_part = line
        
        # Check if pattern is in the code part
        if pattern not in code_part:
            return True  # Pattern is only in the comment
        
        # Check if we're inside a string literal
        # Simple heuristic: count quotes before the pattern
        code_before = code_part[:code_part.find(pattern)]
        
        # Count unescaped quotes
        single_quotes = code_before.count("'") - code_before.count("\\'")
        double_quotes = code_before.count('"') - code_before.count('\\"')
        triple_single = code_before.count("'''")
        triple_double = code_before.count('"""')
        
        # If odd number of quotes before pattern, we're likely inside a string
        if single_quotes % 2 == 1 or double_quotes % 2 == 1:
            return True
        
        if triple_single % 2 == 1 or triple_double % 2 == 1:
            return True
        
        return False
    
    def _is_safe_pattern(self, line: str, rule_id: str) -> bool:
        """
        FIX #2: Recognize safe implementations of dangerous patterns
        Returns True if the pattern is safe and should NOT be flagged
        """
        
        # SC-001: torch.load with weights_only=True is SAFE
        if rule_id == 'SC-001' and 'torch.load' in line:
            if 'weights_only=True' in line:
                return True  # Safe implementation
            if '.safetensors' in line:
                return True  # Safe format
        
        # SC-003: exec/eval in comments or strings is NOT dangerous
        if rule_id == 'SC-003':
            if 'eval(' in line or 'exec(' in line:
                # Check if it's an ORM method
                for orm_method in self.ORM_SAFE_METHODS:
                    if orm_method in line:
                        return True  # It's an ORM method, not dangerous
        
        # SC-007: trust_remote_code=False is safe (but this is default anyway)
        if rule_id == 'SC-007' and 'trust_remote_code' in line:
            if 'trust_remote_code=False' in line:
                return True  # Safe setting
        
        return False
    
    def _is_vulnerable_code(self, line: str, rule_id: str, pattern_type: str) -> Tuple[bool, str]:
        """
        Determine if a line contains a real vulnerability
        Returns (is_vulnerable, reason)
        """
        
        # If it's in a string/comment, not vulnerable
        if self._is_string_or_comment(line, pattern_type):
            return False, "in_string_or_comment"
        
        # If it's a safe pattern, not vulnerable
        if self._is_safe_pattern(line, rule_id):
            return False, "safe_pattern"
        
        return True, "executable_code"
    
    def _calculate_confidence(self, rule_id: str, line: str, base_confidence: float) -> Tuple[float, str]:
        """
        FIX: Adjust confidence based on context
        Returns (adjusted_confidence, false_positive_risk)
        """
        
        false_positive_risk = "low"
        confidence = base_confidence
        
        # Reduce confidence if in test/example context
        if any(x in line for x in ['test', 'example', 'demo', 'proof', 'poc']):
            confidence *= 0.5
            false_positive_risk = "high"
        
        # Reduce confidence if it's a string literal
        if "'" in line or '"' in line:
            confidence *= 0.6
            false_positive_risk = "medium"
        
        # Reduce confidence if it's documentation/comment heavy
        if line.strip().startswith('#'):
            confidence *= 0.1
            false_positive_risk = "high"
        
        # Boost confidence if it's clearly code
        if '=' in line and not line.strip().startswith('#'):
            confidence = min(0.99, confidence * 1.1)
            false_positive_risk = "low"
        
        return confidence, false_positive_risk
    
    def _scan_file(self, file_path: Path, content: str):
        """Scan single file for supply chain vulnerabilities"""
        lines = content.split('\n')
        
        for rule_id, rule_config in self.RULES.items():
            for pattern_tuple in rule_config.get('patterns', []):
                # Unpack pattern and type
                pattern = pattern_tuple[0]
                pattern_type = pattern_tuple[1]
                
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # FIX #1: Check if it's in a string/comment
                        is_vuln, reason = self._is_vulnerable_code(line, rule_id, pattern_type)
                        
                        if not is_vuln:
                            if self.verbose:
                                print(f"[SKIP] {file_path}:{line_num} - {reason}")
                            continue
                        
                        # FIX: Calculate adjusted confidence
                        base_conf = rule_config['confidence']
                        confidence, fp_risk = self._calculate_confidence(rule_id, line, base_conf)
                        
                        finding = SupplyChainFinding(
                            rule_id=rule_id,
                            rule_name=rule_config['name'],
                            severity=rule_config['severity'],
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip()[:100],
                            confidence=confidence,
                            remediation=self.REMEDIATION.get(rule_id, ''),
                            cve_mapping=self.CVE_MAPPINGS.get(rule_id, ''),
                            false_positive_risk=fp_risk,
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
            'version': '2.0.0',
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
    """
    FIX: Realistic bounty estimation without inflated multipliers
    Based on actual Tier-1 program bounty ranges
    """
    
    # Realistic bounty ranges for actual vulnerabilities
    severity_bounties = {
        'critical': (2000, 10000),   # Reduced from 5K-20K
        'high': (500, 3000),         # Reduced from 2K-10K
        'medium': (100, 500),        # Reduced from 500-2K
        'low': (50, 200),            # Reduced from 100-500
    }
    
    total_min = 0
    total_max = 0
    findings_list = report.get('findings', [])
    
    for finding in findings_list:
        severity = finding['severity']
        confidence = finding['confidence']
        
        # Only count high-confidence findings
        if confidence < 0.6:
            continue
        
        min_bounty, max_bounty = severity_bounties.get(severity, (0, 0))
        
        # FIX: Use confidence as a weight, not a multiplier
        # Don't over-inflate by multiplying
        weighted_min = int(min_bounty * confidence)
        weighted_max = int(max_bounty * confidence)
        
        total_min += weighted_min
        total_max += weighted_max
    
    return {
        'estimated_min': total_min,
        'estimated_max': total_max,
        'average_per_finding': int((total_min + total_max) / 2 / max(len([f for f in findings_list if f['confidence'] >= 0.6]), 1)) if findings_list else 0,
        'note': 'Estimates based on Tier-1 programs; actual bounties vary'
    }


if __name__ == '__main__':
    import sys
    
    repo_path = sys.argv[1] if len(sys.argv) > 1 else '.'
    
    engine = Engine5SupplyChainIntelligence(repo_path, verbose=True)
    report = engine.analyze()
    bounty = estimate_bounty_impact(report)
    
    print(f"\n{'='*70}")
    print(f"Engine 5: Supply Chain Intelligence v2.0 - Analysis Report")
    print(f"{'='*70}")
    print(f"Repository: {report['repository']}")
    print(f"Total Findings: {report['total_findings']}")
    print(f"  - Critical: {report['by_severity']['critical']}")
    print(f"  - High: {report['by_severity']['high']}")
    print(f"Supply Chain Risk Score: {report['risk_score']:.1f}/100")
    print(f"Estimated Bounty Impact: ${bounty['estimated_min']:,} - ${bounty['estimated_max']:,}")
    print(f"{'='*70}\n")
    
    # Save report
    output_file = Path(repo_path) / 'engine5_supply_chain_report_v2.json'
    with open(output_file, 'w') as f:
        json.dump({
            **report,
            'bounty_impact': bounty
        }, f, indent=2)
    
    print(f"Report saved to: {output_file}\n")
