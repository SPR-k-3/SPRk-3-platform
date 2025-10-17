#!/usr/bin/env python3
"""
SPR{K}3 Structural Poisoning Detector
======================================

Survival Pattern Recognition {Kinase} with 3 Engines

Based on research: arXiv 2510.07192v1
"Data Poisoning Attacks Require Constant Sample Count"

Key Finding: Just 250 poisoned samples can backdoor models from 600M to 13B parameters.

Three-Engine Architecture:
1. Pattern Detection Engine - Scans code for recurring patterns
2. Bio-Intelligence Engine - Analyzes patterns using evolutionary principles  
3. Decision Engine - Evaluates threat levels and provides actionable insights
"""

import os
import re
import json
import hashlib
import statistics
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, field

# Critical research-based threshold
POISONING_THRESHOLD = 250  # Samples needed for successful poisoning
WARNING_THRESHOLD = 200    # 80% of poisoning threshold
SAFE_THRESHOLD = 50        # Below this is considered safe

@dataclass
class Pattern:
    """Represents a detected pattern in the codebase"""
    content: str
    locations: List[str] = field(default_factory=list)
    count: int = 0
    first_seen: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    contributors: Set[str] = field(default_factory=set)
    risk_score: float = 0.0
    pattern_type: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ThreatSignal:
    """Represents a detected security threat"""
    threat_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    pattern: Pattern
    confidence: float
    description: str
    remediation: str
    evidence: List[str] = field(default_factory=list)

class StructuralPoisoningDetector:
    """Main detector implementing the 3-engine architecture"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.patterns: Dict[str, Pattern] = {}
        self.threat_signals: List[ThreatSignal] = []
        self.scan_metadata = {
            "files_scanned": 0,
            "patterns_detected": 0,
            "threats_found": 0,
            "scan_time": None
        }
        
    def analyze(self, target_path: str) -> Dict[str, Any]:
        """Main analysis entry point"""
        start_time = datetime.now()
        
        if self.verbose:
            print(f"🔬 SPR{{K}}3 Analysis Started: {target_path}")
            
        # Engine 1: Pattern Detection
        self._detect_patterns(target_path)
        
        # Engine 2: Bio-Intelligence Analysis
        self._analyze_evolution()
        
        # Engine 3: Decision Engine
        self._evaluate_threats()
        
        self.scan_metadata["scan_time"] = (datetime.now() - start_time).total_seconds()
        
        return self._generate_report()
    
    def _detect_patterns(self, target_path: str):
        """Engine 1: Pattern Detection"""
        path = Path(target_path)
        
        if path.is_file():
            self._scan_file(path)
        elif path.is_dir():
            for file_path in path.rglob("*"):
                if file_path.is_file() and self._is_scannable(file_path):
                    self._scan_file(file_path)
                    
    def _scan_file(self, file_path: Path):
        """Scan individual file for patterns"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                self.scan_metadata["files_scanned"] += 1
                
                # Detect different pattern types
                self._detect_injection_patterns(content, str(file_path))
                self._detect_backdoor_patterns(content, str(file_path))
                self._detect_config_tampering(content, str(file_path))
                self._detect_obfuscation(content, str(file_path))
                self._detect_exfiltration(content, str(file_path))
                
        except Exception as e:
            if self.verbose:
                print(f"⚠️ Error scanning {file_path}: {e}")
                
    def _detect_injection_patterns(self, content: str, filepath: str):
        """Detect hidden prompt injection patterns"""
        injection_patterns = [
            (r'system\s*prompt.*override', 'System Prompt Override'),
            (r'ignore\s*previous\s*instructions', 'Instruction Override'),
            (r'admin.*mode.*enable', 'Admin Mode Activation'),
            (r'bypass.*security', 'Security Bypass'),
            (r'<!-- hidden:.*?-->', 'Hidden HTML Comment'),
            (r'/\*\s*hidden:.*?\*/', 'Hidden Code Comment'),
        ]
        
        for pattern, pattern_name in injection_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                self._record_pattern(
                    match.group(0), 
                    filepath, 
                    "injection",
                    {"subtype": pattern_name}
                )
                
    def _detect_backdoor_patterns(self, content: str, filepath: str):
        """Detect backdoor trigger patterns"""
        backdoor_patterns = [
            (r'if\s+\w+\s*==\s*["\']magic_key["\']', 'Magic Key Check'),
            (r'eval\([^)]*user_input[^)]*\)', 'Eval User Input'),
            (r'exec\([^)]*request\.[^)]*\)', 'Exec Request Data'),
            (r'__import__\(["\']os["\']\)\.system', 'OS Command Execution'),
        ]
        
        for pattern, pattern_name in backdoor_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self._record_pattern(
                    match.group(0),
                    filepath,
                    "backdoor", 
                    {"subtype": pattern_name}
                )
                
    def _detect_config_tampering(self, content: str, filepath: str):
        """Detect ML configuration tampering"""
        config_patterns = [
            (r'learning_rate\s*=\s*[\d.]+', 'Learning Rate'),
            (r'batch_size\s*=\s*\d+', 'Batch Size'),
            (r'epochs?\s*=\s*\d+', 'Training Epochs'),
            (r'dropout\s*=\s*[\d.]+', 'Dropout Rate'),
        ]
        
        for pattern, config_name in config_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Extract the value for analysis
                value_match = re.search(r'[\d.]+$', match.group(0))
                if value_match:
                    try:
                        value = float(value_match.group(0))
                        # Check for suspicious values
                        if config_name == 'Learning Rate' and value > 1.0:
                            self._record_pattern(
                                match.group(0),
                                filepath,
                                "config_tampering",
                                {"config": config_name, "value": value, "suspicious": True}
                            )
                        elif config_name == 'Dropout Rate' and value > 0.9:
                            self._record_pattern(
                                match.group(0),
                                filepath,
                                "config_tampering", 
                                {"config": config_name, "value": value, "suspicious": True}
                            )
                    except ValueError:
                        pass
                        
    def _detect_obfuscation(self, content: str, filepath: str):
        """Detect code obfuscation attempts"""
        obfuscation_patterns = [
            (r'eval\s*\([^)]+\)', 'Eval Statement'),
            (r'exec\s*\([^)]+\)', 'Exec Statement'),
            (r'compile\s*\([^)]+\)', 'Compile Statement'),
            (r'__import__\s*\([^)]+\)', 'Dynamic Import'),
            (r'base64\.b64decode', 'Base64 Decoding'),
            (r'\\x[0-9a-f]{2}', 'Hex Encoding'),
        ]
        
        for pattern, obfuscation_type in obfuscation_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self._record_pattern(
                    match.group(0),
                    filepath,
                    "obfuscation",
                    {"subtype": obfuscation_type}
                )
                
    def _detect_exfiltration(self, content: str, filepath: str):
        """Detect potential data exfiltration"""
        exfil_patterns = [
            (r'https?://[^\s\'"]+', 'External URL'),
            (r'requests\.(get|post)\([^)]+\)', 'HTTP Request'),
            (r'urllib.*urlopen\([^)]+\)', 'URL Open'),
            (r'socket\.(connect|send)\([^)]+\)', 'Socket Connection'),
        ]
        
        for pattern, exfil_type in exfil_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Check if it's a suspicious domain
                if 'External URL' in exfil_type:
                    url = match.group(0)
                    if any(suspicious in url for suspicious in ['evil', 'malicious', 'attacker', 'c2server']):
                        self._record_pattern(
                            match.group(0),
                            filepath,
                            "exfiltration",
                            {"subtype": exfil_type, "suspicious": True}
                        )
                else:
                    self._record_pattern(
                        match.group(0),
                        filepath,
                        "exfiltration",
                        {"subtype": exfil_type}
                    )
                    
    def _record_pattern(self, content: str, filepath: str, pattern_type: str, metadata: Dict = None):
        """Record a detected pattern"""
        pattern_hash = hashlib.md5(content.encode()).hexdigest()
        
        if pattern_hash not in self.patterns:
            self.patterns[pattern_hash] = Pattern(
                content=content[:100],  # Truncate for display
                locations=[filepath],
                count=1,
                first_seen=datetime.now(),
                last_modified=datetime.now(),
                pattern_type=pattern_type,
                metadata=metadata or {}
            )
            self.scan_metadata["patterns_detected"] += 1
        else:
            pattern = self.patterns[pattern_hash]
            if filepath not in pattern.locations:
                pattern.locations.append(filepath)
            pattern.count += 1
            pattern.last_modified = datetime.now()
            
    def _analyze_evolution(self):
        """Engine 2: Bio-Intelligence Analysis using evolutionary principles"""
        for pattern in self.patterns.values():
            # Calculate pattern velocity (spread rate)
            if pattern.count > 1:
                time_span = (pattern.last_modified - pattern.first_seen).total_seconds()
                if time_span > 0:
                    velocity = pattern.count / (time_span / 3600)  # patterns per hour
                    pattern.metadata["velocity"] = velocity
                    
            # Calculate architectural impact
            pattern.metadata["blast_radius"] = len(pattern.locations)
            
            # Risk scoring based on pattern characteristics
            risk_score = 0.0
            
            # Factor 1: Pattern count approaching threshold
            if pattern.count >= WARNING_THRESHOLD:
                risk_score += 0.8
            elif pattern.count >= SAFE_THRESHOLD:
                risk_score += 0.4
                
            # Factor 2: Pattern type severity
            type_severity = {
                "injection": 0.9,
                "backdoor": 1.0,
                "config_tampering": 0.7,
                "obfuscation": 0.6,
                "exfiltration": 0.8
            }
            risk_score += type_severity.get(pattern.pattern_type, 0.5)
            
            # Factor 3: Suspicious metadata
            if pattern.metadata.get("suspicious"):
                risk_score += 0.3
                
            # Factor 4: Velocity (rapid spread)
            if pattern.metadata.get("velocity", 0) > 10:
                risk_score += 0.5
                
            pattern.risk_score = min(risk_score, 1.0)  # Cap at 1.0
            
    def _evaluate_threats(self):
        """Engine 3: Decision Engine - evaluate and classify threats"""
        for pattern in self.patterns.values():
            # Determine if pattern constitutes a threat
            if pattern.count >= POISONING_THRESHOLD:
                threat = ThreatSignal(
                    threat_type=f"POISONING_ATTACK_{pattern.pattern_type.upper()}",
                    severity="CRITICAL",
                    pattern=pattern,
                    confidence=0.95,
                    description=f"Detected {pattern.count} instances of {pattern.pattern_type} pattern - exceeds poisoning threshold",
                    remediation="Immediate investigation required. Pattern count exceeds research-proven poisoning threshold.",
                    evidence=pattern.locations[:5]  # First 5 locations as evidence
                )
                self.threat_signals.append(threat)
                self.scan_metadata["threats_found"] += 1
                
            elif pattern.count >= WARNING_THRESHOLD:
                threat = ThreatSignal(
                    threat_type=f"POISONING_WARNING_{pattern.pattern_type.upper()}",
                    severity="HIGH",
                    pattern=pattern,
                    confidence=0.75,
                    description=f"Pattern approaching poisoning threshold: {pattern.count}/{POISONING_THRESHOLD}",
                    remediation="Monitor closely. Pattern count approaching critical threshold.",
                    evidence=pattern.locations[:3]
                )
                self.threat_signals.append(threat)
                self.scan_metadata["threats_found"] += 1
                
            elif pattern.risk_score > 0.7:
                threat = ThreatSignal(
                    threat_type=f"SUSPICIOUS_PATTERN_{pattern.pattern_type.upper()}",
                    severity="MEDIUM",
                    pattern=pattern,
                    confidence=0.6,
                    description=f"Suspicious {pattern.pattern_type} pattern detected",
                    remediation="Review pattern for potential security implications.",
                    evidence=pattern.locations[:2]
                )
                self.threat_signals.append(threat)
                self.scan_metadata["threats_found"] += 1
                
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""
        report = {
            "summary": {
                "status": self._get_overall_status(),
                "files_scanned": self.scan_metadata["files_scanned"],
                "patterns_detected": self.scan_metadata["patterns_detected"],
                "threats_found": self.scan_metadata["threats_found"],
                "scan_duration": f"{self.scan_metadata['scan_time']:.2f}s" if self.scan_metadata['scan_time'] else "N/A"
            },
            "threats": [],
            "patterns": [],
            "recommendations": []
        }
        
        # Add threat details
        for threat in sorted(self.threat_signals, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[x.severity]):
            report["threats"].append({
                "type": threat.threat_type,
                "severity": threat.severity,
                "confidence": f"{threat.confidence:.1%}",
                "description": threat.description,
                "pattern_count": threat.pattern.count,
                "locations": len(threat.pattern.locations),
                "remediation": threat.remediation
            })
            
        # Add pattern analysis
        for pattern in sorted(self.patterns.values(), key=lambda x: x.risk_score, reverse=True)[:10]:
            report["patterns"].append({
                "type": pattern.pattern_type,
                "count": pattern.count,
                "risk_score": f"{pattern.risk_score:.2f}",
                "locations": len(pattern.locations),
                "velocity": pattern.metadata.get("velocity", 0),
                "sample": pattern.content[:50] + "..." if len(pattern.content) > 50 else pattern.content
            })
            
        # Generate recommendations
        if any(t.severity == "CRITICAL" for t in self.threat_signals):
            report["recommendations"].append("🚨 IMMEDIATE ACTION: Critical poisoning threshold exceeded. Quarantine affected systems.")
        if any(t.severity == "HIGH" for t in self.threat_signals):
            report["recommendations"].append("⚠️ HIGH PRIORITY: Patterns approaching poisoning threshold. Initiate security review.")
        if self.scan_metadata["patterns_detected"] > 100:
            report["recommendations"].append("📊 Consider implementing continuous pattern monitoring.")
            
        return report
        
    def _get_overall_status(self) -> str:
        """Determine overall security status"""
        if any(t.severity == "CRITICAL" for t in self.threat_signals):
            return "🔴 CRITICAL - Poisoning Attack Detected"
        elif any(t.severity == "HIGH" for t in self.threat_signals):
            return "🟠 HIGH RISK - Approaching Poisoning Threshold"
        elif any(t.severity == "MEDIUM" for t in self.threat_signals):
            return "🟡 MEDIUM RISK - Suspicious Patterns Detected"
        else:
            return "🟢 SECURE - No Significant Threats Detected"
            
    def _is_scannable(self, file_path: Path) -> bool:
        """Check if file should be scanned"""
        # Skip binary and system files
        skip_extensions = {'.pyc', '.pyo', '.so', '.dll', '.exe', '.bin', '.dat', '.db', '.sqlite'}
        skip_dirs = {'__pycache__', '.git', 'node_modules', 'venv', '.env'}
        
        if file_path.suffix in skip_extensions:
            return False
            
        for parent in file_path.parents:
            if parent.name in skip_dirs:
                return False
                
        return True

# CLI Interface
if __name__ == "__main__":
    import sys
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║      SPR{K}3 - Structural Poisoning Detector v1.0           ║
║   Protecting ML Pipelines from 250-Sample Attacks           ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage: python sprk3_complete.py <target_path>")
        sys.exit(1)
        
    target = sys.argv[1]
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    
    detector = StructuralPoisoningDetector(verbose=verbose)
    report = detector.analyze(target)
    
    # Print report
    print(f"\n📊 Analysis Complete: {report['summary']['status']}")
    print(f"   Files Scanned: {report['summary']['files_scanned']}")
    print(f"   Patterns Detected: {report['summary']['patterns_detected']}")
    print(f"   Threats Found: {report['summary']['threats_found']}")
    print(f"   Scan Duration: {report['summary']['scan_duration']}")
    
    if report["threats"]:
        print("\n🚨 Threat Summary:")
        for threat in report["threats"]:
            print(f"   [{threat['severity']}] {threat['type']}")
            print(f"          Pattern Count: {threat['pattern_count']}")
            print(f"          Confidence: {threat['confidence']}")
            print(f"          Action: {threat['remediation']}")
            
    if report["recommendations"]:
        print("\n💡 Recommendations:")
        for rec in report["recommendations"]:
            print(f"   {rec}")
            
    # Export detailed report
    if "--export" in sys.argv:
        output_file = "sprk3_report.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n📄 Detailed report exported to: {output_file}")
