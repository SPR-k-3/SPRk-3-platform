"""
SPR{K}3 - Survival Pattern Recognition Kinase (3 Engines)
Bio-inspired code intelligence for pattern detection and ML security

Core detection engine powering both:
1. Architectural Intelligence (SPDR3) - Survivor pattern detection
2. Security Monitoring (Sentinel) - ML poisoning detection
"""

import re
import ast
import json
from datetime import datetime
from typing import Dict, List, Tuple, Set, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path


@dataclass
class Pattern:
    """Detected pattern in code"""
    pattern_type: str  # 'timeout', 'port', 'config', 'ml_param', etc.
    pattern_value: str
    file_path: str
    line_number: int
    context: str
    confidence: float
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    occurrence_count: int = 1
    files_affected: Set[str] = field(default_factory=set)
    
    def __hash__(self):
        return hash((self.pattern_type, self.pattern_value))


@dataclass
class AnalysisResult:
    """Results from SPR{K}3 analysis"""
    patterns: List[Pattern]
    survivor_patterns: List[Pattern]  # For SPDR3
    security_alerts: List[Dict]  # For Sentinel
    statistics: Dict
    recommendations: List[str]
    timestamp: datetime = field(default_factory=datetime.utcnow)


class SPRK3Engine:
    """
    Core SPR{K}3 detection engine
    
    Three-engine architecture:
    1. Detection Engine: Find patterns
    2. Intelligence Engine: Analyze significance  
    3. Decision Engine: Generate recommendations
    """
    
    # Pattern detection regexes
    PATTERNS = {
        'timeout': r'timeout[_\s]*=[\s]*(\d+)',
        'port': r'port[_\s]*=[\s]*(\d+)',
        'max_retries': r'max[_\s]*retries[_\s]*=[\s]*(\d+)',
        'buffer_size': r'buffer[_\s]*size[_\s]*=[\s]*(\d+)',
        'thread_count': r'thread[s]?[_\s]*=[\s]*(\d+)',
        'batch_size': r'batch[_\s]*size[_\s]*=[\s]*(\d+)',
        'learning_rate': r'learning[_\s]*rate[_\s]*=[\s]*([\d.]+)',
        'epochs': r'epochs[_\s]*=[\s]*(\d+)',
        'hidden_dim': r'hidden[_\s]*dim[_\s]*=[\s]*(\d+)',
    }
    
    # Security-specific patterns (for Sentinel)
    SECURITY_PATTERNS = {
        'prompt_injection': r'(system|user|assistant)[_\s]*prompt[_\s]*=[\s]*["\'](.{20,})["\']',
        'backdoor_trigger': r'(trigger|activation|backdoor)[_\s]*=[\s]*["\'](.{10,})["\']',
        'data_exfiltration': r'(http://|https://|ftp://)(external|remote|upload)',
        'obfuscation': r'(eval|exec|compile)\s*\(',
        'hardcoded_secret': r'(api[_\s]*key|secret[_\s]*key|password)[_\s]*=[\s]*["\'][^"\']{10,}["\']',
    }
    
    def __init__(self):
        self.patterns_detected: Dict[str, List[Pattern]] = defaultdict(list)
        self.file_count = 0
        self.line_count = 0
        
    def analyze_codebase(self, codebase_path: str) -> AnalysisResult:
        """
        Main analysis entry point
        
        Args:
            codebase_path: Path to codebase directory
            
        Returns:
            AnalysisResult with patterns, alerts, and recommendations
        """
        codebase = Path(codebase_path)
        
        # Scan all Python files
        for py_file in codebase.rglob("*.py"):
            if self._should_skip_file(py_file):
                continue
            self._analyze_file(py_file)
            
        # Generate results
        return self._generate_results()
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Skip test files, migrations, etc."""
        skip_dirs = {'.git', '__pycache__', 'node_modules', 'venv', '.venv', 'migrations'}
        return any(skip_dir in file_path.parts for skip_dir in skip_dirs)
    
    def _analyze_file(self, file_path: Path):
        """Analyze a single file for patterns"""
        try:
            content = file_path.read_text(encoding='utf-8')
            self.file_count += 1
            lines = content.split('\n')
            self.line_count += len(lines)
            
            # Detect architectural patterns
            for pattern_type, regex in self.PATTERNS.items():
                self._find_patterns(file_path, content, lines, pattern_type, regex)
            
            # Detect security patterns (for Sentinel)
            for pattern_type, regex in self.SECURITY_PATTERNS.items():
                self._find_security_patterns(file_path, content, lines, pattern_type, regex)
                
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
    
    def _find_patterns(self, file_path: Path, content: str, lines: List[str], 
                      pattern_type: str, regex: str):
        """Find architectural patterns in file"""
        for match in re.finditer(regex, content, re.IGNORECASE):
            line_num = content[:match.start()].count('\n') + 1
            context = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            
            pattern = Pattern(
                pattern_type=pattern_type,
                pattern_value=match.group(1),
                file_path=str(file_path),
                line_number=line_num,
                context=context,
                confidence=0.8,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                files_affected={str(file_path)}
            )
            
            self.patterns_detected[pattern_type].append(pattern)
    
    def _find_security_patterns(self, file_path: Path, content: str, lines: List[str],
                               pattern_type: str, regex: str):
        """Find security-related patterns (for Sentinel)"""
        for match in re.finditer(regex, content, re.IGNORECASE):
            line_num = content[:match.start()].count('\n') + 1
            context = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            
            pattern = Pattern(
                pattern_type=f"security_{pattern_type}",
                pattern_value=match.group(0)[:50],  # Truncate for safety
                file_path=str(file_path),
                line_number=line_num,
                context=context[:100],  # Truncate context
                confidence=0.7,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                files_affected={str(file_path)}
            )
            
            self.patterns_detected[f"security_{pattern_type}"].append(pattern)
    
    def _generate_results(self) -> AnalysisResult:
        """Generate final analysis results"""
        all_patterns = []
        for patterns in self.patterns_detected.values():
            all_patterns.extend(patterns)
        
        # Identify survivor patterns (appear in 3+ files)
        pattern_frequencies = defaultdict(int)
        for pattern in all_patterns:
            key = (pattern.pattern_type, pattern.pattern_value)
            pattern_frequencies[key] += 1
        
        survivor_patterns = [
            p for p in all_patterns
            if pattern_frequencies[(p.pattern_type, p.pattern_value)] >= 3
        ]
        
        # Identify security alerts
        security_alerts = [
            {
                'type': p.pattern_type,
                'severity': 'high' if 'backdoor' in p.pattern_type or 'injection' in p.pattern_type else 'medium',
                'file': p.file_path,
                'line': p.line_number,
                'description': f"Detected {p.pattern_type} pattern",
                'confidence': p.confidence
            }
            for p in all_patterns
            if p.pattern_type.startswith('security_')
        ]
        
        # Generate statistics
        statistics = {
            'files_analyzed': self.file_count,
            'lines_analyzed': self.line_count,
            'patterns_detected': len(all_patterns),
            'survivor_patterns': len(survivor_patterns),
            'security_alerts': len(security_alerts),
            'pattern_types': len(set(p.pattern_type for p in all_patterns))
        }
        
        # Generate recommendations
        recommendations = self._generate_recommendations(all_patterns, survivor_patterns, security_alerts)
        
        return AnalysisResult(
            patterns=all_patterns,
            survivor_patterns=survivor_patterns,
            security_alerts=security_alerts,
            statistics=statistics,
            recommendations=recommendations
        )
    
    def _generate_recommendations(self, all_patterns: List[Pattern], 
                                 survivor_patterns: List[Pattern],
                                 security_alerts: List[Dict]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # SPDR3 recommendations
        if survivor_patterns:
            recommendations.append(
                f"🏗️ Found {len(survivor_patterns)} survivor patterns - these may be load-bearing. "
                "Review before refactoring."
            )
        
        # Sentinel recommendations
        if security_alerts:
            high_severity = sum(1 for alert in security_alerts if alert['severity'] == 'high')
            if high_severity > 0:
                recommendations.append(
                    f"🛡️ CRITICAL: {high_severity} high-severity security alerts detected. "
                    "Review immediately."
                )
            else:
                recommendations.append(
                    f"🛡️ {len(security_alerts)} security patterns detected. Review recommended."
                )
        
        # Pattern diversity recommendation
        pattern_types = set(p.pattern_type for p in all_patterns)
        if len(pattern_types) > 10:
            recommendations.append(
                f"📊 High pattern diversity ({len(pattern_types)} types). "
                "Consider standardization."
            )
        
        return recommendations


def main():
    """CLI entry point"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python sprk3_engine.py <codebase_path>")
        sys.exit(1)
    
    codebase_path = sys.argv[1]
    print(f"🔬 SPR{{K}}3 Engine - Analyzing {codebase_path}...")
    print("=" * 70)
    
    engine = SPRK3Engine()
    result = engine.analyze_codebase(codebase_path)
    
    # Print results
    print(f"\n📊 Analysis Complete")
    print(f"Files analyzed: {result.statistics['files_analyzed']}")
    print(f"Lines analyzed: {result.statistics['lines_analyzed']}")
    print(f"Patterns detected: {result.statistics['patterns_detected']}")
    print(f"Survivor patterns: {result.statistics['survivor_patterns']}")
    print(f"Security alerts: {result.statistics['security_alerts']}")
    
    if result.security_alerts:
        print(f"\n🛡️ Security Alerts:")
        for alert in result.security_alerts[:5]:  # Show first 5
            print(f"  - {alert['severity'].upper()}: {alert['description']} ({alert['file']}:{alert['line']})")
    
    if result.recommendations:
        print(f"\n💡 Recommendations:")
        for rec in result.recommendations:
            print(f"  {rec}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
