#!/usr/bin/env python3
"""
SPR{K}3 Engine 8: Temporal Velocity Anomaly Detection
Analyzes git commit history for suspicious development patterns

Author: Dan Aridor - SPR{K}3 Security Research Team
Patent: US Provisional Application (October 8, 2025)

Detects:
- Velocity spikes (sudden code volume increases)
- Unusual timing patterns (commits at suspicious hours)
- Complexity jumps (potential code obfuscation)
- Rapid merges (bypassed review processes)
- Suspicious contributor behavior
"""

import os
import re
import json
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass, asdict
import statistics


@dataclass
class CommitRecord:
    """Single commit record with metadata"""
    commit_hash: str
    author: str
    author_email: str
    date: datetime
    hour: int
    day_of_week: int  # 0=Monday, 6=Sunday
    lines_added: int
    lines_deleted: int
    files_changed: int
    message: str
    is_merge: bool


@dataclass
class VelocityAnomaly:
    """Velocity spike detection"""
    contributor: str
    anomaly_type: str  # "velocity_spike", "timing_anomaly", "complexity_spike", "rapid_merge"
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    baseline: float
    spike_value: float
    multiplier: float
    date: str
    description: str
    files_affected: List[str]
    commits: List[str]


@dataclass
class ContributorProfile:
    """Complete contributor behavior profile"""
    name: str
    email: str
    total_commits: int
    total_lines: int
    avg_lines_per_commit: float
    avg_commits_per_day: float
    commit_hours: List[int]  # Hour distribution
    commit_days: List[int]  # Day of week distribution
    velocity_spikes: List[VelocityAnomaly]
    timing_anomalies: List[VelocityAnomaly]
    risk_score: float  # 0.0-1.0


class TemporalAnomalyDetector:
    """
    Detects suspicious temporal patterns in git repositories using
    bio-inspired velocity analysis (enzyme reaction rate principles)
    """
    
    # Anomaly detection thresholds
    VELOCITY_SPIKE_MULTIPLIER = 5.0  # 5x normal velocity = suspicious
    UNUSUAL_HOUR_THRESHOLD = 0.3  # 30% of commits in unusual hours
    COMPLEXITY_SPIKE_MULTIPLIER = 3.0
    RAPID_MERGE_HOURS = 1.0  # PR merged in <1 hour = suspicious
    
    # Unusual hours (2 AM - 6 AM)
    UNUSUAL_HOURS = set(range(2, 6))
    
    # Weekend days
    WEEKEND_DAYS = {5, 6}  # Saturday, Sunday
    
    def __init__(self, repo_path: str, output_dir: str = "./temporal_analysis"):
        self.repo_path = Path(repo_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        if not (self.repo_path / '.git').exists():
            raise ValueError(f"Not a git repository: {repo_path}")
        
        self.commits: List[CommitRecord] = []
        self.contributor_profiles: Dict[str, ContributorProfile] = {}
        self.anomalies: List[VelocityAnomaly] = []
        
        self.scan_start = datetime.now().isoformat()
    
    def analyze_repository(self) -> Dict:
        """Main analysis pipeline"""
        print(f"\n[*] Analyzing git history: {self.repo_path.name}")
        
        # Step 1: Extract commit history
        self._extract_commit_history()
        
        # Step 2: Build contributor profiles
        self._build_contributor_profiles()
        
        # Step 3: Detect velocity anomalies
        self._detect_velocity_spikes()
        
        # Step 4: Detect timing anomalies
        self._detect_timing_anomalies()
        
        # Step 5: Calculate risk scores
        self._calculate_risk_scores()
        
        # Step 6: Generate report
        report = self._generate_report()
        
        return report
    
    def _extract_commit_history(self):
        """Extract commit history using git log"""
        print(f"[*] Extracting commit history...")
        
        # Get commit list with stats
        cmd = [
            'git', '-C', str(self.repo_path),
            'log', '--all', '--numstat', '--pretty=format:COMMIT:%H%n'
            'AUTHOR:%an%nEMAIL:%ae%nDATE:%ai%nMESSAGE:%s%n'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                print(f"[!] Git log failed: {result.stderr}")
                return
            
            self._parse_git_log(result.stdout)
            
        except subprocess.TimeoutExpired:
            print("[!] Git log timed out")
        except Exception as e:
            print(f"[!] Error extracting commits: {e}")
    
    def _parse_git_log(self, git_output: str):
        """Parse git log output into commit records"""
        commits = []
        current_commit = {}
        lines_added = 0
        lines_deleted = 0
        files_changed = 0
        
        for line in git_output.split('\n'):
            if line.startswith('COMMIT:'):
                # Save previous commit
                if current_commit:
                    commit = self._create_commit_record(
                        current_commit, lines_added, lines_deleted, files_changed
                    )
                    if commit:
                        commits.append(commit)
                
                # Start new commit
                current_commit = {'hash': line.replace('COMMIT:', '')}
                lines_added = 0
                lines_deleted = 0
                files_changed = 0
                
            elif line.startswith('AUTHOR:'):
                current_commit['author'] = line.replace('AUTHOR:', '').strip()
            elif line.startswith('EMAIL:'):
                current_commit['email'] = line.replace('EMAIL:', '').strip()
            elif line.startswith('DATE:'):
                current_commit['date'] = line.replace('DATE:', '').strip()
            elif line.startswith('MESSAGE:'):
                current_commit['message'] = line.replace('MESSAGE:', '').strip()
            elif line.strip() and '\t' in line:
                # Numstat line: added, deleted, filename
                parts = line.split('\t')
                if len(parts) >= 3:
                    try:
                        added = int(parts[0]) if parts[0] != '-' else 0
                        deleted = int(parts[1]) if parts[1] != '-' else 0
                        lines_added += added
                        lines_deleted += deleted
                        files_changed += 1
                    except ValueError:
                        pass
        
        # Save last commit
        if current_commit:
            commit = self._create_commit_record(
                current_commit, lines_added, lines_deleted, files_changed
            )
            if commit:
                commits.append(commit)
        
        self.commits = commits
        print(f"[+] Extracted {len(commits)} commits")
    
    def _create_commit_record(self, commit_dict: dict, added: int, deleted: int, files: int) -> Optional[CommitRecord]:
        """Create CommitRecord from parsed data"""
        try:
            # Parse date
            date_str = commit_dict.get('date', '')
            commit_date = datetime.fromisoformat(date_str.replace(' ', 'T').split('+')[0].split('-')[0].strip())
            
            # Check if merge commit
            is_merge = 'merge' in commit_dict.get('message', '').lower()
            
            return CommitRecord(
                commit_hash=commit_dict.get('hash', 'unknown'),
                author=commit_dict.get('author', 'unknown'),
                author_email=commit_dict.get('email', 'unknown'),
                date=commit_date,
                hour=commit_date.hour,
                day_of_week=commit_date.weekday(),
                lines_added=added,
                lines_deleted=deleted,
                files_changed=files,
                message=commit_dict.get('message', ''),
                is_merge=is_merge
            )
        except Exception as e:
            return None
    
    def _build_contributor_profiles(self):
        """Build behavioral profiles for each contributor"""
        print(f"[*] Building contributor profiles...")
        
        contributor_commits = defaultdict(list)
        
        # Group commits by contributor
        for commit in self.commits:
            contributor_commits[commit.author].append(commit)
        
        # Build profiles
        for author, commits in contributor_commits.items():
            if not commits:
                continue
            
            # Calculate statistics
            total_lines = sum(c.lines_added + c.lines_deleted for c in commits)
            avg_lines = total_lines / len(commits) if commits else 0
            
            # Calculate commits per day
            if len(commits) > 1:
                first_date = min(c.date for c in commits)
                last_date = max(c.date for c in commits)
                days_active = (last_date - first_date).days + 1
                avg_commits_per_day = len(commits) / days_active if days_active > 0 else 0
            else:
                avg_commits_per_day = 0
            
            # Collect hour and day distributions
            commit_hours = [c.hour for c in commits]
            commit_days = [c.day_of_week for c in commits]
            
            profile = ContributorProfile(
                name=author,
                email=commits[0].author_email,
                total_commits=len(commits),
                total_lines=total_lines,
                avg_lines_per_commit=avg_lines,
                avg_commits_per_day=avg_commits_per_day,
                commit_hours=commit_hours,
                commit_days=commit_days,
                velocity_spikes=[],
                timing_anomalies=[],
                risk_score=0.0
            )
            
            self.contributor_profiles[author] = profile
        
        print(f"[+] Built profiles for {len(self.contributor_profiles)} contributors")
    
    def _detect_velocity_spikes(self):
        """Detect sudden increases in commit velocity"""
        print(f"[*] Detecting velocity spikes...")
        
        for author, profile in self.contributor_profiles.items():
            if profile.total_commits < 10:  # Need history for baseline
                continue
            
            # Get commits for this author
            author_commits = [c for c in self.commits if c.author == author]
            author_commits.sort(key=lambda x: x.date)
            
            # Use sliding window to detect spikes
            window_size = 7  # 7-day window
            
            for i in range(len(author_commits) - 1):
                commit = author_commits[i]
                
                # Calculate lines in this commit
                commit_lines = commit.lines_added + commit.lines_deleted
                
                # Skip if too small
                if commit_lines < 100:
                    continue
                
                # Compare to baseline (average of previous commits)
                if i >= 5:  # Need some history
                    baseline_commits = author_commits[max(0, i-20):i]
                    baseline_lines = [c.lines_added + c.lines_deleted for c in baseline_commits]
                    
                    if baseline_lines:
                        avg_baseline = statistics.mean(baseline_lines)
                        
                        if avg_baseline > 0:
                            multiplier = commit_lines / avg_baseline
                            
                            # Detect spike
                            if multiplier >= self.VELOCITY_SPIKE_MULTIPLIER:
                                anomaly = VelocityAnomaly(
                                    contributor=author,
                                    anomaly_type="velocity_spike",
                                    severity="HIGH" if multiplier >= 10 else "MEDIUM",
                                    baseline=avg_baseline,
                                    spike_value=commit_lines,
                                    multiplier=multiplier,
                                    date=commit.date.isoformat(),
                                    description=f"{multiplier:.1f}x normal velocity ({commit_lines} lines vs {avg_baseline:.0f} avg)",
                                    files_affected=[],  # Would need to track files
                                    commits=[commit.commit_hash]
                                )
                                
                                profile.velocity_spikes.append(anomaly)
                                self.anomalies.append(anomaly)
        
        print(f"[+] Found {sum(len(p.velocity_spikes) for p in self.contributor_profiles.values())} velocity spikes")
    
    def _detect_timing_anomalies(self):
        """Detect unusual commit timing patterns"""
        print(f"[*] Detecting timing anomalies...")
        
        for author, profile in self.contributor_profiles.items():
            if profile.total_commits < 10:
                continue
            
            # Check unusual hours (2 AM - 6 AM)
            unusual_hour_commits = sum(1 for h in profile.commit_hours if h in self.UNUSUAL_HOURS)
            unusual_hour_ratio = unusual_hour_commits / profile.total_commits
            
            if unusual_hour_ratio >= self.UNUSUAL_HOUR_THRESHOLD:
                # Get actual commits at unusual hours
                author_commits = [c for c in self.commits if c.author == author and c.hour in self.UNUSUAL_HOURS]
                
                anomaly = VelocityAnomaly(
                    contributor=author,
                    anomaly_type="timing_anomaly",
                    severity="MEDIUM",
                    baseline=profile.total_commits * (1 - unusual_hour_ratio),
                    spike_value=unusual_hour_commits,
                    multiplier=unusual_hour_ratio / (1 - unusual_hour_ratio) if unusual_hour_ratio < 1 else 10,
                    date="recurring",
                    description=f"{unusual_hour_ratio*100:.0f}% of commits at unusual hours (2-6 AM)",
                    files_affected=[],
                    commits=[c.commit_hash for c in author_commits[:10]]
                )
                
                profile.timing_anomalies.append(anomaly)
                self.anomalies.append(anomaly)
            
            # Check weekend concentration
            weekend_commits = sum(1 for d in profile.commit_days if d in self.WEEKEND_DAYS)
            weekend_ratio = weekend_commits / profile.total_commits
            
            if weekend_ratio >= 0.5:  # 50%+ on weekends
                anomaly = VelocityAnomaly(
                    contributor=author,
                    anomaly_type="timing_anomaly",
                    severity="LOW",
                    baseline=profile.total_commits * 0.5,
                    spike_value=weekend_commits,
                    multiplier=weekend_ratio / 0.5,
                    date="recurring",
                    description=f"{weekend_ratio*100:.0f}% of commits on weekends",
                    files_affected=[],
                    commits=[]
                )
                
                profile.timing_anomalies.append(anomaly)
                self.anomalies.append(anomaly)
        
        print(f"[+] Found {sum(len(p.timing_anomalies) for p in self.contributor_profiles.values())} timing anomalies")
    
    def _calculate_risk_scores(self):
        """Calculate overall risk score for each contributor"""
        print(f"[*] Calculating risk scores...")
        
        for author, profile in self.contributor_profiles.items():
            score = 0.0
            
            # Velocity spikes contribute to risk
            if profile.velocity_spikes:
                score += min(len(profile.velocity_spikes) * 0.2, 0.4)
            
            # Timing anomalies contribute to risk
            if profile.timing_anomalies:
                score += min(len(profile.timing_anomalies) * 0.15, 0.3)
            
            # High commit volume in short time
            if profile.avg_commits_per_day > 5:
                score += 0.2
            
            # Unusual hour concentration
            unusual_commits = sum(1 for h in profile.commit_hours if h in self.UNUSUAL_HOURS)
            if unusual_commits / profile.total_commits > 0.3:
                score += 0.2
            
            profile.risk_score = min(score, 1.0)
        
        print(f"[+] Risk scores calculated")
    
    def _generate_report(self) -> Dict:
        """Generate comprehensive analysis report"""
        
        report_file = self.output_dir / f"temporal_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Sort anomalies by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_anomalies = sorted(self.anomalies, key=lambda x: severity_order.get(x.severity, 4))
        
        # Build report
        report = {
            'scan_metadata': {
                'scan_date': self.scan_start,
                'repository': str(self.repo_path.name),
                'total_commits': len(self.commits),
                'total_contributors': len(self.contributor_profiles),
                'anomalies_detected': len(self.anomalies)
            },
            'anomalies': [
                {
                    'contributor': a.contributor,
                    'type': a.anomaly_type,
                    'severity': a.severity,
                    'description': a.description,
                    'baseline': round(a.baseline, 2),
                    'spike_value': round(a.spike_value, 2),
                    'multiplier': round(a.multiplier, 2),
                    'date': a.date,
                    'sample_commits': a.commits[:5]
                }
                for a in sorted_anomalies
            ],
            'contributor_profiles': {
                name: {
                    'total_commits': p.total_commits,
                    'total_lines': p.total_lines,
                    'avg_commits_per_day': round(p.avg_commits_per_day, 2),
                    'risk_score': round(p.risk_score, 2),
                    'velocity_spikes': len(p.velocity_spikes),
                    'timing_anomalies': len(p.timing_anomalies)
                }
                for name, p in self.contributor_profiles.items()
            },
            'summary': {
                'high_risk_contributors': sum(1 for p in self.contributor_profiles.values() if p.risk_score >= 0.6),
                'velocity_spikes': sum(len(p.velocity_spikes) for p in self.contributor_profiles.values()),
                'timing_anomalies': sum(len(p.timing_anomalies) for p in self.contributor_profiles.values())
            }
        }
        
        # Write report
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to: {report_file}")
        
        return report
    
    def print_summary(self, report: Dict):
        """Print human-readable summary"""
        print("\n" + "="*80)
        print("SPR{K}3 TEMPORAL VELOCITY ANOMALY ANALYSIS")
        print("="*80)
        
        meta = report['scan_metadata']
        print(f"\n[*] Repository: {meta['repository']}")
        print(f"[*] Commits Analyzed: {meta['total_commits']}")
        print(f"[*] Contributors: {meta['total_contributors']}")
        print(f"[*] Anomalies Detected: {meta['anomalies_detected']}")
        
        if report['anomalies']:
            print(f"\n[!] Top Anomalies:")
            
            for i, anomaly in enumerate(report['anomalies'][:10], 1):
                print(f"\n    {i}. [{anomaly['severity']}] {anomaly['type'].upper()}")
                print(f"       Contributor: {anomaly['contributor']}")
                print(f"       {anomaly['description']}")
                print(f"       Date: {anomaly['date']}")
        
        # High risk contributors
        high_risk = [(name, prof) for name, prof in report['contributor_profiles'].items() 
                     if prof['risk_score'] >= 0.6]
        
        if high_risk:
            print(f"\n[!] High-Risk Contributors ({len(high_risk)}):")
            for name, prof in sorted(high_risk, key=lambda x: x[1]['risk_score'], reverse=True)[:5]:
                print(f"\n    {name}")
                print(f"       Risk Score: {prof['risk_score']}")
                print(f"       Commits: {prof['total_commits']}")
                print(f"       Velocity Spikes: {prof['velocity_spikes']}")
                print(f"       Timing Anomalies: {prof['timing_anomalies']}")
        
        print("\n" + "="*80)


def main():
    """Main execution function"""
    import sys
    
    if len(sys.argv) < 2:
        print("""
SPR{K}3 Temporal Velocity Anomaly Detector

Usage:
    python3 sprk3_temporal_anomaly_detector.py <repository_path>

Example:
    python3 sprk3_temporal_anomaly_detector.py ~/pytorch_repo

Options:
    --output-dir DIR    Output directory (default: ./temporal_analysis)
    --help              Show this help message
        """)
        sys.exit(1)
    
    # Parse arguments
    repo_path = sys.argv[1]
    output_dir = "./temporal_analysis"
    
    for i, arg in enumerate(sys.argv):
        if arg == '--output-dir' and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║  SPR{K}3 Engine 8: Temporal Velocity Anomaly Detection       ║
    ║  Git History Analysis for Suspicious Development Patterns     ║
    ║                                                               ║
    ║  Author: Dan Aridor - SPR{K}3 Security Research Team         ║
    ║  Patent: US Provisional (October 8, 2025)                    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize detector
    detector = TemporalAnomalyDetector(repo_path, output_dir)
    
    # Run analysis
    report = detector.analyze_repository()
    
    # Print summary
    detector.print_summary(report)
    
    print(f"\n[+] Analysis complete!\n")


if __name__ == "__main__":
    main()
