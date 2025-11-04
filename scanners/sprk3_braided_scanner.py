#!/usr/bin/env python3
"""
SPR{K}3 Engine 7: Braided Supply Chain Intelligence
Cross-Repository Coordinated Attack Detection System

Author: Dan Aridor - SPR{K}3 Security Research Team
Patent: US Provisional Application filed October 8, 2025

This scanner detects coordinated attacks spanning multiple repositories through:
1. Cross-repo pattern correlation (1-250 file attack threshold)
2. Temporal attack staging detection (time-delayed exploitation)
3. Contributor behavior analysis across projects
4. Dependency chain poisoning detection
"""

import os
import re
import json
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass, asdict


@dataclass
class PatternOccurrence:
    """Records a single occurrence of a security pattern"""
    repo_name: str
    file_path: str
    line_number: int
    pattern_type: str
    code_snippet: str
    contributor: str
    commit_hash: str
    commit_date: str
    pattern_hash: str


@dataclass
class CoordinatedAttack:
    """Represents a potential coordinated attack or systematic pattern across repositories"""
    attack_id: str
    pattern_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    classification: str  # Systematic Pattern, Correlated Pattern, Highly Correlated Pattern, Potential Coordinated Attack
    repos_affected: List[str]
    total_occurrences: int
    contributors: List[str]
    timeline_days: int
    first_seen: str
    last_seen: str
    occurrences: List[PatternOccurrence]
    coordination_score: float  # 0.0-1.0


class BraidedScanner:
    """
    Multi-repository security pattern analyzer using bio-inspired correlation.
    
    Implements the "Braided Scan" methodology:
    - Scans multiple repos simultaneously
    - Correlates patterns across codebases
    - Detects temporal staging of attacks
    - Identifies suspicious contributor behavior
    """
    
    # Dangerous patterns to detect (CWE-502 family)
    PATTERNS = {
        'pickle_loads': {
            'regex': r'pickle\.loads?\s*\(',
            'severity': 'CRITICAL',
            'description': 'Unsafe deserialization vulnerability',
            'filter_methods': False  # pickle.loads is always suspicious
        },
        'torch_load': {
            'regex': r'torch\.load\s*\([^)]*(?!weights_only\s*=\s*True)',
            'severity': 'HIGH',
            'description': 'Unsafe model loading without weights_only=True',
            'filter_methods': False
        },
        'exec_call': {
            'regex': r'\bexec\s*\(',
            'severity': 'HIGH',
            'description': 'Dynamic code execution vulnerability',
            'filter_methods': True,  # Filter .exec() method calls
            'method_pattern': r'\.\s*exec\s*\('
        },
        'eval_call': {
            'regex': r'\beval\s*\(',
            'severity': 'MEDIUM',
            'description': 'Code evaluation vulnerability',
            'filter_methods': True,  # Filter .eval() method calls
            'method_pattern': r'\.\s*eval\s*\('
        },
        'yaml_load': {
            'regex': r'yaml\.load\s*\([^)]*(?!Loader\s*=)',
            'severity': 'HIGH',
            'description': 'Unsafe YAML loading',
            'filter_methods': False
        },
        'subprocess_shell': {
            'regex': r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
            'severity': 'MEDIUM',
            'description': 'Shell injection vulnerability',
            'filter_methods': False
        }
    }
    
    def __init__(self, output_dir: str = "./braided_scan_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Cross-repo correlation storage
        self.pattern_memory: Dict[str, List[PatternOccurrence]] = defaultdict(list)
        self.contributor_patterns: Dict[str, List[PatternOccurrence]] = defaultdict(list)
        self.repo_metadata: Dict[str, dict] = {}
        
        self.scan_start = datetime.now().isoformat()
        
    def scan_repository(self, repo_path: str) -> Dict[str, List[PatternOccurrence]]:
        """
        Scan a single repository for dangerous patterns.
        
        Args:
            repo_path: Path to git repository
            
        Returns:
            Dictionary mapping pattern types to occurrences
        """
        repo_path = Path(repo_path)
        if not repo_path.exists():
            print(f"[!] Repository not found: {repo_path}")
            return {}
        
        repo_name = repo_path.name
        print(f"\n[*] Scanning repository: {repo_name}")
        
        occurrences: Dict[str, List[PatternOccurrence]] = defaultdict(list)
        
        # Find all Python files
        python_files = list(repo_path.rglob("*.py"))
        
        # Filter out test files, examples, and common false positive directories
        python_files = [
            f for f in python_files 
            if not any(exclude in str(f) for exclude in [
                '/test/', '/tests/', '/testing/',
                '/example/', '/examples/',
                '/demo/', '/demos/',
                '/benchmark/', '/benchmarks/',
                '/.git/', '/build/', '/dist/',
                '__pycache__', '.pytest_cache'
            ])
        ]
        
        print(f"[*] Analyzing {len(python_files)} Python files...")
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                for pattern_name, pattern_info in self.PATTERNS.items():
                    for line_num, line in enumerate(lines, 1):
                        if re.search(pattern_info['regex'], line):
                            # Filter out method calls if configured
                            if pattern_info.get('filter_methods', False):
                                method_pattern = pattern_info.get('method_pattern')
                                if method_pattern and re.search(method_pattern, line):
                                    # This is a method call like .eval() or .exec(), skip it
                                    continue
                            
                            # Get git blame information
                            blame_info = self._get_git_blame(repo_path, py_file, line_num)
                            
                            # Create pattern hash for correlation
                            pattern_hash = self._create_pattern_hash(
                                pattern_name, 
                                line.strip()
                            )
                            
                            occurrence = PatternOccurrence(
                                repo_name=repo_name,
                                file_path=str(py_file.relative_to(repo_path)),
                                line_number=line_num,
                                pattern_type=pattern_name,
                                code_snippet=line.strip()[:200],
                                contributor=blame_info['author'],
                                commit_hash=blame_info['commit'],
                                commit_date=blame_info['date'],
                                pattern_hash=pattern_hash
                            )
                            
                            occurrences[pattern_name].append(occurrence)
                            
                            # Add to cross-repo memory
                            self.pattern_memory[pattern_hash].append(occurrence)
                            self.contributor_patterns[blame_info['author']].append(occurrence)
                            
            except Exception as e:
                # Skip files that can't be read
                continue
        
        # Store repo metadata
        self.repo_metadata[repo_name] = {
            'path': str(repo_path),
            'files_scanned': len(python_files),
            'patterns_found': sum(len(occs) for occs in occurrences.values())
        }
        
        print(f"[+] Found {sum(len(v) for v in occurrences.values())} total pattern occurrences")
        
        return occurrences
    
    def _get_git_blame(self, repo_path: Path, file_path: Path, line_num: int) -> dict:
        """Get git blame information for a specific line"""
        try:
            rel_path = file_path.relative_to(repo_path)
            cmd = ['git', '-C', str(repo_path), 'blame', '-L', 
                   f'{line_num},{line_num}', '--porcelain', str(rel_path)]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                commit = lines[0].split()[0] if lines else 'unknown'
                
                author = 'unknown'
                date = 'unknown'
                for line in lines:
                    if line.startswith('author '):
                        author = line.replace('author ', '').strip()
                    elif line.startswith('author-time '):
                        timestamp = int(line.replace('author-time ', '').strip())
                        date = datetime.fromtimestamp(timestamp).isoformat()
                
                return {'author': author, 'commit': commit, 'date': date}
        except Exception:
            pass
        
        return {'author': 'unknown', 'commit': 'unknown', 'date': 'unknown'}
    
    def _create_pattern_hash(self, pattern_type: str, code: str) -> str:
        """Create a hash for pattern correlation across repos"""
        # Normalize code for comparison
        normalized = re.sub(r'\s+', ' ', code.strip().lower())
        normalized = re.sub(r'["\'].*?["\']', 'STRING', normalized)  # Replace strings
        normalized = re.sub(r'\d+', 'NUM', normalized)  # Replace numbers
        
        hash_input = f"{pattern_type}:{normalized}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    
    def detect_coordinated_attacks(self) -> List[CoordinatedAttack]:
        """
        Analyze cross-repo patterns to detect coordinated attacks.
        
        Uses SPR{K}3's bio-inspired correlation to identify:
        1. Same patterns across multiple repos
        2. Same contributors introducing patterns
        3. Temporal staging (patterns appearing over time)
        4. Suspicious concentration of dangerous code
        """
        print("\n[*] Analyzing cross-repository pattern correlations...")
        
        coordinated_attacks = []
        processed_combinations = set()
        
        # 1. Detect cross-repo pattern correlation by exact code match
        for pattern_hash, occurrences in self.pattern_memory.items():
            if len(occurrences) < 2:  # Need at least 2 repos
                continue
            
            repos_affected = set(occ.repo_name for occ in occurrences)
            if len(repos_affected) < 2:
                continue
            
            # Create unique identifier for this attack
            attack_key = f"{pattern_hash}:{','.join(sorted(repos_affected))}"
            if attack_key in processed_combinations:
                continue
            processed_combinations.add(attack_key)
            
            # Calculate coordination score
            contributors = set(occ.contributor for occ in occurrences)
            
            # Get temporal spread
            dates = [occ.commit_date for occ in occurrences if occ.commit_date != 'unknown']
            if dates:
                dates_sorted = sorted(dates)
                first_seen = dates_sorted[0]
                last_seen = dates_sorted[-1]
                
                # Calculate days between first and last occurrence
                try:
                    first_dt = datetime.fromisoformat(first_seen)
                    last_dt = datetime.fromisoformat(last_seen)
                    timeline_days = (last_dt - first_dt).days
                except:
                    timeline_days = 0
            else:
                first_seen = "unknown"
                last_seen = "unknown"
                timeline_days = 0
            
            # Coordination score calculation
            # Higher score = more suspicious
            score = 0.0
            
            # Same contributor across repos = very suspicious
            if len(contributors) == 1 and len(repos_affected) >= 2:
                score += 0.5
            
            # Temporal staging (90-365 days apart) = suspicious
            if 90 <= timeline_days <= 365:
                score += 0.3
            
            # Many repos affected = suspicious
            score += min(len(repos_affected) * 0.1, 0.3)
            
            # Determine severity
            pattern_type = occurrences[0].pattern_type
            base_severity = self.PATTERNS[pattern_type]['severity']
            
            # Upgrade severity if coordinated
            if score >= 0.7 and base_severity == 'HIGH':
                severity = 'CRITICAL'
            elif score >= 0.5:
                severity = 'HIGH'
            elif base_severity == 'CRITICAL':
                severity = 'CRITICAL'
            else:
                severity = base_severity
            
            attack = CoordinatedAttack(
                attack_id=f"COORD_{pattern_hash}",
                pattern_type=pattern_type,
                severity=severity,
                repos_affected=sorted(list(repos_affected)),
                total_occurrences=len(occurrences),
                contributors=sorted(list(contributors)),
                timeline_days=timeline_days,
                first_seen=first_seen,
                last_seen=last_seen,
                occurrences=occurrences,
                coordination_score=score
            )
            
            coordinated_attacks.append(attack)
        
        # 2. Detect same pattern_type + contributor across multiple repos
        # This catches coordinated attacks even if code differs slightly
        contributor_pattern_combos = defaultdict(lambda: defaultdict(list))
        
        for contributor, occurrences in self.contributor_patterns.items():
            if contributor == 'unknown':
                continue
            
            for occ in occurrences:
                contributor_pattern_combos[contributor][occ.pattern_type].append(occ)
        
        for contributor, pattern_types in contributor_pattern_combos.items():
            for pattern_type, occurrences in pattern_types.items():
                repos_affected = set(occ.repo_name for occ in occurrences)
                
                # Need pattern in at least 2 repos
                if len(repos_affected) < 2:
                    continue
                
                # Create unique identifier
                attack_key = f"{contributor}:{pattern_type}:{','.join(sorted(repos_affected))}"
                if attack_key in processed_combinations:
                    continue
                processed_combinations.add(attack_key)
                
                # Get temporal spread
                dates = [occ.commit_date for occ in occurrences if occ.commit_date != 'unknown']
                if dates:
                    dates_sorted = sorted(dates)
                    first_seen = dates_sorted[0]
                    last_seen = dates_sorted[-1]
                    
                    try:
                        first_dt = datetime.fromisoformat(first_seen)
                        last_dt = datetime.fromisoformat(last_seen)
                        timeline_days = (last_dt - first_dt).days
                    except:
                        timeline_days = 0
                else:
                    first_seen = "unknown"
                    last_seen = "unknown"
                    timeline_days = 0
                
                # Coordination score calculation
                score = 0.0
                
                # CRITICAL: Same contributor + same pattern type across repos = very suspicious
                score += 0.6
                
                # Temporal staging (90-365 days apart) = staged attack indicator
                if 90 <= timeline_days <= 365:
                    score += 0.3
                elif timeline_days > 0:
                    score += 0.1
                
                # Multiple repos affected = broader impact
                score += min(len(repos_affected) * 0.05, 0.2)
                
                # Determine severity and classification
                base_severity = self.PATTERNS[pattern_type]['severity']
                classification = "Systematic Pattern"
                
                # Upgrade severity and classification if highly coordinated
                if score >= 0.8 and base_severity in ['HIGH', 'CRITICAL']:
                    severity = 'CRITICAL'
                    classification = "Potential Coordinated Attack"
                elif score >= 0.7:
                    severity = 'CRITICAL' if base_severity == 'CRITICAL' else 'HIGH'
                    classification = "Highly Correlated Pattern"
                elif score >= 0.6 and base_severity == 'HIGH':
                    severity = 'CRITICAL'
                    classification = "Correlated Pattern"
                elif score >= 0.6:
                    severity = 'HIGH'
                    classification = "Correlated Pattern"
                else:
                    severity = base_severity
                    classification = "Systematic Pattern"
                
                # Generate unique attack ID
                pattern_hash = hashlib.sha256(attack_key.encode()).hexdigest()[:16]
                
                attack = CoordinatedAttack(
                    attack_id=f"COORD_{pattern_hash}",
                    pattern_type=pattern_type,
                    severity=severity,
                    classification=classification,
                    repos_affected=sorted(list(repos_affected)),
                    total_occurrences=len(occurrences),
                    contributors=[contributor],
                    timeline_days=timeline_days,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    occurrences=occurrences,
                    coordination_score=score
                )
                
                coordinated_attacks.append(attack)
        
        # Sort by coordination score (highest first)
        coordinated_attacks.sort(key=lambda x: x.coordination_score, reverse=True)
        
        print(f"[+] Detected {len(coordinated_attacks)} potential coordinated attacks")
        
        return coordinated_attacks
    
    def generate_report(self, coordinated_attacks: List[CoordinatedAttack]) -> str:
        """Generate comprehensive analysis report"""
        
        report_file = self.output_dir / f"braided_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Build report structure
        report = {
            'scan_metadata': {
                'scan_date': self.scan_start,
                'scanner_version': 'SPR{K}3 Engine 7 v1.0',
                'repositories_scanned': len(self.repo_metadata),
                'total_patterns_found': sum(
                    repo['patterns_found'] for repo in self.repo_metadata.values()
                )
            },
            'repositories': self.repo_metadata,
            'coordinated_attacks': [],
            'contributor_risk_profile': self._build_contributor_profiles(),
            'summary': {
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'low_findings': 0,
                'cross_repo_correlations': len(coordinated_attacks)
            }
        }
        
        # Add coordinated attacks
        for attack in coordinated_attacks:
            attack_dict = {
                'attack_id': attack.attack_id,
                'severity': attack.severity,
                'classification': attack.classification,
                'pattern_type': attack.pattern_type,
                'pattern_description': self.PATTERNS[attack.pattern_type]['description'],
                'coordination_score': round(attack.coordination_score, 3),
                'repos_affected': attack.repos_affected,
                'total_occurrences': attack.total_occurrences,
                'contributors': attack.contributors,
                'temporal_analysis': {
                    'first_seen': attack.first_seen,
                    'last_seen': attack.last_seen,
                    'timeline_days': attack.timeline_days,
                    'staging_indicator': 90 <= attack.timeline_days <= 365
                },
                'occurrences': [
                    {
                        'repo': occ.repo_name,
                        'file': occ.file_path,
                        'line': occ.line_number,
                        'contributor': occ.contributor,
                        'commit': occ.commit_hash[:8],
                        'date': occ.commit_date,
                        'code': occ.code_snippet
                    }
                    for occ in attack.occurrences
                ]
            }
            
            report['coordinated_attacks'].append(attack_dict)
            
            # Update summary counts
            if attack.severity == 'CRITICAL':
                report['summary']['critical_findings'] += 1
            elif attack.severity == 'HIGH':
                report['summary']['high_findings'] += 1
            elif attack.severity == 'MEDIUM':
                report['summary']['medium_findings'] += 1
            else:
                report['summary']['low_findings'] += 1
        
        # Write report
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to: {report_file}")
        
        return str(report_file)
    
    def _build_contributor_profiles(self) -> dict:
        """Build risk profiles for contributors across repos"""
        profiles = {}
        
        for contributor, occurrences in self.contributor_patterns.items():
            if contributor == 'unknown':
                continue
            
            repos = set(occ.repo_name for occ in occurrences)
            patterns = set(occ.pattern_type for occ in occurrences)
            
            # Risk scoring
            risk_score = 0.0
            
            # Multiple repos = higher risk
            if len(repos) >= 3:
                risk_score += 0.4
            elif len(repos) == 2:
                risk_score += 0.2
            
            # Multiple dangerous patterns = higher risk
            if len(patterns) >= 3:
                risk_score += 0.4
            elif len(patterns) == 2:
                risk_score += 0.2
            
            # Many occurrences = higher risk
            if len(occurrences) >= 10:
                risk_score += 0.2
            
            profiles[contributor] = {
                'repos_contributed': sorted(list(repos)),
                'pattern_types': sorted(list(patterns)),
                'total_occurrences': len(occurrences),
                'risk_score': round(min(risk_score, 1.0), 3)
            }
        
        return profiles
    
    def print_summary(self, coordinated_attacks: List[CoordinatedAttack]):
        """Print human-readable summary"""
        print("\n" + "="*80)
        print("SPR{K}3 BRAIDED SCAN SUMMARY")
        print("="*80)
        
        print(f"\n[*] Repositories Scanned: {len(self.repo_metadata)}")
        for repo_name, metadata in self.repo_metadata.items():
            print(f"    - {repo_name}: {metadata['patterns_found']} patterns in {metadata['files_scanned']} files")
        
        print(f"\n[*] Cross-Repository Correlations Found: {len(coordinated_attacks)}")
        
        if coordinated_attacks:
            critical = [a for a in coordinated_attacks if a.severity == 'CRITICAL']
            high = [a for a in coordinated_attacks if a.severity == 'HIGH']
            medium = [a for a in coordinated_attacks if a.severity == 'MEDIUM']
            
            print(f"    - CRITICAL: {len(critical)}")
            print(f"    - HIGH: {len(high)}")
            print(f"    - MEDIUM: {len(medium)}")
            
            print("\n[!] Top 5 Cross-Repository Pattern Correlations:")
            for i, attack in enumerate(coordinated_attacks[:5], 1):
                print(f"\n    {i}. [{attack.severity}] {attack.pattern_type.upper()}")
                print(f"       Classification: {attack.classification}")
                print(f"       Coordination Score: {attack.coordination_score:.2f}")
                print(f"       Repos: {', '.join(attack.repos_affected)}")
                print(f"       Contributors: {', '.join(attack.contributors[:3])}")
                print(f"       Timeline: {attack.timeline_days} days")
                print(f"       Occurrences: {attack.total_occurrences}")
        
        print("\n" + "="*80)


def main():
    """Main execution function"""
    import sys
    
    if len(sys.argv) < 2:
        print("""
SPR{K}3 Braided Scanner - Cross-Repository Coordinated Attack Detection

Usage:
    python3 sprk3_braided_scanner.py <repo1> <repo2> [repo3] ...

Example:
    python3 sprk3_braided_scanner.py ./pytorch ./torchvision ./transformers

Options:
    --output-dir DIR    Output directory (default: ./braided_scan_results)
    --help             Show this help message
        """)
        sys.exit(1)
    
    # Parse arguments
    repos = [arg for arg in sys.argv[1:] if not arg.startswith('--')]
    output_dir = "./braided_scan_results"
    
    for i, arg in enumerate(sys.argv):
        if arg == '--output-dir' and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║  SPR{K}3 Engine 7: Braided Supply Chain Intelligence         ║
    ║  Cross-Repository Coordinated Attack Detection                ║
    ║                                                               ║
    ║  Author: Dan Aridor - SPR{K}3 Security Research Team         ║
    ║  Patent: US Provisional (October 8, 2025)                    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize scanner
    scanner = BraidedScanner(output_dir=output_dir)
    
    # Scan all repositories
    for repo in repos:
        scanner.scan_repository(repo)
    
    # Detect coordinated attacks
    coordinated_attacks = scanner.detect_coordinated_attacks()
    
    # Generate reports
    report_file = scanner.generate_report(coordinated_attacks)
    scanner.print_summary(coordinated_attacks)
    
    print(f"\n[+] Full report: {report_file}")
    print(f"[+] Scan complete!\n")


if __name__ == "__main__":
    main()
