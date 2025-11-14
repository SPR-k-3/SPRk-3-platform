#!/usr/bin/env python3
"""
SPR{K}3 TEMPORAL INTELLIGENCE ENGINE v1.0
==========================================

Detects backdoors and suspicious patterns in git history by analyzing:
1. Commit velocity anomalies (sudden bursts of commits)
2. Rapid code insertions (malicious patches hidden in activity)
3. Unusual contributor patterns (new actors making critical changes)
4. Temporal clustering (multiple changes concentrated in short timeframes)
5. Dangerous function introduction timing

Uses statistical anomaly detection to flag suspicious temporal patterns.
"""

import os
import subprocess
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter
import statistics

class TemporalIntelligence:
    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.vulnerabilities = []
        self.temporal_patterns = defaultdict(list)
        self.commit_history = []
        
    def run_git_command(self, command):
        """Execute git command in repo"""
        try:
            result = subprocess.run(
                f"cd {self.repo_path} && {command}",
        # SECURITY FIX: Changed shell=True to shell=False
                shell=False,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout.strip()
        except Exception as e:
            print(f"Error running git command: {e}")
            return ""
    
    def extract_commit_history(self):
        """Extract full commit history with timestamps and diffs"""
        print("[*] Extracting git commit history...")
        
        # Get all commits with metadata
        command = 'git log --all --pretty=format:"%H|%an|%ae|%ai|%s" --name-status'
        output = self.run_git_command(command)
        
        current_commit = None
        for line in output.split('\n'):
            if '|' in line and len(line.split('|')) == 5:
                parts = line.split('|')
                current_commit = {
                    'hash': parts[0],
                    'author': parts[1],
                    'email': parts[2],
                    'timestamp': datetime.fromisoformat(parts[3].replace('Z', '+00:00')),
                    'message': parts[4],
                    'files': []
                }
                self.commit_history.append(current_commit)
        
        print(f"[+] Extracted {len(self.commit_history)} commits")
        return self.commit_history
    
    def detect_velocity_anomalies(self):
        """Detect suspicious commit velocity patterns"""
        print("[*] Analyzing commit velocity patterns...")
        
        # Group commits by hour
        commits_per_hour = defaultdict(int)
        for commit in self.commit_history:
            hour_key = commit['timestamp'].strftime("%Y-%m-%d %H:00")
            commits_per_hour[hour_key] += 1
        
        # Calculate statistics
        if not commits_per_hour:
            return
            
        velocities = list(commits_per_hour.values())
        mean_velocity = statistics.mean(velocities)
        stdev_velocity = statistics.stdev(velocities) if len(velocities) > 1 else 0
        
        # Flag anomalies (>2 standard deviations)
        threshold = mean_velocity + (2 * stdev_velocity)
        
        for hour, count in commits_per_hour.items():
            if count > threshold:
                self.vulnerabilities.append({
                    'type': 'VELOCITY_ANOMALY',
                    'severity': 'HIGH',
                    'timestamp': hour,
                    'commit_count': count,
                    'threshold': threshold,
                    'z_score': (count - mean_velocity) / (stdev_velocity + 0.001),
                    'bounty': '$10K-$50K',
                    'description': f'Suspicious commit velocity spike: {count} commits in {hour}'
                })
        
        print(f"[+] Found {len([v for v in self.vulnerabilities if v['type'] == 'VELOCITY_ANOMALY'])} velocity anomalies")
    
    def detect_dangerous_functions_introduction(self):
        """Detect when dangerous functions are introduced"""
        print("[*] Analyzing dangerous function introductions...")
        
        dangerous_patterns = {
            'eval': r'\beval\s*\(',
            'exec': r'\bexec\s*\(',
            'pickle.load': r'pickle\.load\s*\(',
            'torch.load': r'torch\.load\s*\(',
            'subprocess.shell': r'subprocess.*shell\s*=\s*True',
            '__import__': r'__import__\s*\(',
            'compile': r'\bcompile\s*\(',
        }
        
        for commit_idx, commit in enumerate(self.commit_history):
            # Get diff for this commit
            diff_cmd = f'git show {commit["hash"]} --no-patch --format="" -p'
            diff_output = self.run_git_command(diff_cmd)
            
            for dangerous_func, pattern in dangerous_patterns.items():
                # Look for lines added (starting with +)
                for line in diff_output.split('\n'):
                    if line.startswith('+') and not line.startswith('+++'):
                        if re.search(pattern, line):
                            # Calculate recency score (newer = more suspicious)
                            days_ago = (datetime.now(commit['timestamp'].tzinfo) - commit['timestamp']).days
                            recency_score = 100 - min(days_ago, 100)  # 0-100
                            
                            self.vulnerabilities.append({
                                'type': 'DANGEROUS_FUNCTION_INTRODUCTION',
                                'severity': 'CRITICAL' if recency_score > 80 else 'HIGH',
                                'function': dangerous_func,
                                'commit': commit['hash'][:7],
                                'author': commit['author'],
                                'timestamp': commit['timestamp'].isoformat(),
                                'days_ago': days_ago,
                                'recency_score': recency_score,
                                'bounty': '$25K-$100K' if recency_score > 80 else '$10K-$50K',
                                'description': f'{dangerous_func} introduced by {commit["author"]} ({days_ago} days ago)',
                                'code': line[:100]
                            })
        
        print(f"[+] Found {len([v for v in self.vulnerabilities if v['type'] == 'DANGEROUS_FUNCTION_INTRODUCTION'])} dangerous functions introduced")
    
    def detect_contributor_anomalies(self):
        """Detect unusual contributor patterns"""
        print("[*] Analyzing contributor patterns...")
        
        # Track contributors and their activity
        contributor_commits = defaultdict(list)
        for commit in self.commit_history:
            contributor_commits[commit['author']].append(commit)
        
        total_commits = len(self.commit_history)
        
        for author, commits in contributor_commits.items():
            commit_count = len(commits)
            percentage = (commit_count / total_commits) * 100 if total_commits > 0 else 0
            
            # Check for new contributors making many commits suddenly
            if commit_count > 10:
                first_commit = min(commits, key=lambda c: c['timestamp'])
                last_commit = max(commits, key=lambda c: c['timestamp'])
                
                # If all commits happen within 7 days, it's suspicious
                time_span = (last_commit['timestamp'] - first_commit['timestamp']).days
                if time_span < 7 and time_span > 0:
                    activity_burst = commit_count / time_span
                    
                    self.vulnerabilities.append({
                        'type': 'CONTRIBUTOR_ANOMALY',
                        'severity': 'HIGH',
                        'author': author,
                        'commit_count': commit_count,
                        'percentage': f"{percentage:.1f}%",
                        'time_span_days': time_span,
                        'activity_burst': f"{activity_burst:.1f} commits/day",
                        'bounty': '$15K-$75K',
                        'description': f'Suspicious contributor activity: {author} made {commit_count} commits in {time_span} days'
                    })
        
        print(f"[+] Found {len([v for v in self.vulnerabilities if v['type'] == 'CONTRIBUTOR_ANOMALY'])} contributor anomalies")
    
    def detect_large_file_introductions(self):
        """Detect suspicious large file additions"""
        print("[*] Analyzing large file introductions...")
        
        for commit in self.commit_history:
            size_cmd = f'git show {commit["hash"]}:$(git ls-tree -r {commit["hash"]} | sort -k4 -rn | head -1 | awk "{{print $4}}")' 
            
            # Alternative: get largest file added in this commit
            diff_cmd = f'git show {commit["hash"]} --stat'
            diff_output = self.run_git_command(diff_cmd)
            
            # Parse diff stat for large additions
            for line in diff_output.split('\n'):
                if ' | ' in line:
                    parts = line.split('|')
                    if len(parts) == 2:
                        try:
                            changes = parts[1].strip().split()
                            if changes:
                                insertion_count = int(changes[0].replace('+', '').replace('-', ''))
                                if insertion_count > 5000:  # Suspicious if >5K lines added
                                    self.vulnerabilities.append({
                                        'type': 'LARGE_FILE_ADDITION',
                                        'severity': 'MEDIUM',
                                        'commit': commit['hash'][:7],
                                        'author': commit['author'],
                                        'file': parts[0].strip(),
                                        'insertions': insertion_count,
                                        'timestamp': commit['timestamp'].isoformat(),
                                        'bounty': '$5K-$25K',
                                        'description': f'Large file addition: {insertion_count} lines in {parts[0].strip()}'
                                    })
                        except:
                            pass
        
        print(f"[+] Found {len([v for v in self.vulnerabilities if v['type'] == 'LARGE_FILE_ADDITION'])} large file additions")
    
    def detect_temporal_clustering(self):
        """Detect temporal clustering of suspicious changes"""
        print("[*] Analyzing temporal clustering patterns...")
        
        if len(self.commit_history) < 10:
            return
        
        # Look for clusters of commits within 1-hour windows
        for i in range(len(self.commit_history) - 5):
            window_commits = self.commit_history[i:i+6]
            first_time = window_commits[0]['timestamp']
            last_time = window_commits[-1]['timestamp']
            
            time_delta = (last_time - first_time).total_seconds() / 60  # minutes
            
            if 0 < time_delta < 60:  # 6 commits within 1 hour
                # Check for variety of files
                files_modified = set()
                for commit in window_commits:
                    files_modified.add(commit.get('files', [''])[0])
                
                if len(files_modified) > 3:
                    self.vulnerabilities.append({
                        'type': 'TEMPORAL_CLUSTERING',
                        'severity': 'MEDIUM',
                        'cluster_size': len(window_commits),
                        'time_window_minutes': time_delta,
                        'files_modified': len(files_modified),
                        'bounty': '$10K-$40K',
                        'description': f'Suspicious temporal cluster: {len(window_commits)} commits in {time_delta:.0f} minutes'
                    })
        
        print(f"[+] Found {len([v for v in self.vulnerabilities if v['type'] == 'TEMPORAL_CLUSTERING'])} temporal clusters")
    
    def generate_report(self):
        """Generate comprehensive temporal analysis report"""
        print("\n" + "="*80)
        print("SPR{K}3 TEMPORAL INTELLIGENCE REPORT")
        print("="*80)
        
        if not self.vulnerabilities:
            print("\n[+] No suspicious temporal patterns detected")
            return
        
        # Group by type
        by_type = defaultdict(list)
        for vuln in self.vulnerabilities:
            by_type[vuln['type']].append(vuln)
        
        total_severity_score = 0
        
        for vuln_type, vulns in sorted(by_type.items()):
            print(f"\n{vuln_type}:")
            print(f"  Found: {len(vulns)} instances")
            
            for vuln in vulns[:3]:  # Show top 3
                print(f"\n  [{vuln.get('severity', 'UNKNOWN')}]")
                print(f"  {vuln.get('description', vuln)}")
                if 'bounty' in vuln:
                    print(f"  Bounty: {vuln['bounty']}")
        
        print(f"\n{'='*80}")
        print(f"TOTAL FINDINGS: {len(self.vulnerabilities)}")
        print(f"ESTIMATED BOUNTY: ${len(self.vulnerabilities) * 15}K - ${len(self.vulnerabilities) * 50}K")
        print("="*80)
    
    def scan(self):
        """Run complete temporal intelligence scan"""
        print("\n" + "="*80)
        print("SPR{K}3 TEMPORAL INTELLIGENCE ENGINE v1.0")
        print("="*80)
        print(f"Scanning: {self.repo_path}\n")
        
        try:
            self.extract_commit_history()
            self.detect_velocity_anomalies()
            self.detect_dangerous_functions_introduction()
            self.detect_contributor_anomalies()
            self.detect_temporal_clustering()
            self.detect_large_file_introductions()
            self.generate_report()
            
            return self.vulnerabilities
        except Exception as e:
            print(f"Error during scan: {e}")
            return []

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 sprk3_temporal_intelligence_v1.py <repo_path>")
        print("Example: python3 sprk3_temporal_intelligence_v1.py /tmp/bentoml")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    
    if not os.path.exists(repo_path):
        print(f"Error: Repository not found at {repo_path}")
        sys.exit(1)
    
    scanner = TemporalIntelligence(repo_path)
    vulnerabilities = scanner.scan()
    
    # Output JSON for further analysis
    print(f"\nJSON Output:")
    print(json.dumps(vulnerabilities, indent=2, default=str))
