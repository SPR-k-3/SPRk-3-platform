#!/usr/bin/env python3
"""
SPR{K}3 Temporal Velocity Anomaly Detector - Fixed Version
Simple git log parsing that actually works
"""
import subprocess
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import statistics

repo_path = Path.home() / "pytorch_repo"
output_dir = Path("./temporal_analysis")
output_dir.mkdir(exist_ok=True)

print("Extracting commits (this takes 2-3 minutes)...")

# Get all commits with simple format
cmd = ['git', '-C', str(repo_path), 'log', '--all', '--pretty=format:%H|%an|%ae|%ai|%s']
result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

commits = []
for line in result.stdout.strip().split('\n'):
    if '|' in line:
        parts = line.split('|', 4)
        if len(parts) == 5:
            try:
                date_str = parts[3].split()[0] + ' ' + parts[3].split()[1]
                commit_date = datetime.fromisoformat(date_str.replace(' ', 'T'))
                commits.append({
                    'hash': parts[0],
                    'author': parts[1],
                    'email': parts[2],
                    'date': commit_date,
                    'hour': commit_date.hour,
                    'message': parts[4]
                })
            except:
                pass

print(f"✅ Extracted {len(commits)} commits")
print(f"Building profiles...")

# Build contributor profiles
contributors = defaultdict(lambda: {'commits': [], 'hours': []})
for commit in commits:
    author = commit['author']
    contributors[author]['commits'].append(commit)
    contributors[author]['hours'].append(commit['hour'])

print(f"✅ {len(contributors)} contributors")

# Detect timing anomalies
unusual_hours = {2, 3, 4, 5}
anomalies = []

for author, data in contributors.items():
    if len(data['commits']) < 10:
        continue
    
    unusual = sum(1 for h in data['hours'] if h in unusual_hours)
    ratio = unusual / len(data['commits'])
    
    if ratio >= 0.3:
        anomalies.append({
            'author': author,
            'total_commits': len(data['commits']),
            'unusual_hour_commits': unusual,
            'unusual_ratio': ratio,
            'risk_score': min(ratio * 2, 1.0)
        })

print(f"✅ {len(anomalies)} timing anomalies detected")

# Find Yuanyuan Chen specifically
print("\n" + "="*80)
print("YUANYUAN CHEN ANALYSIS")
print("="*80)

if 'Yuanyuan Chen' in contributors:
    chen_data = contributors['Yuanyuan Chen']
    print(f"Total commits: {len(chen_data['commits'])}")
    print(f"Hour distribution:")
    
    hour_counts = defaultdict(int)
    for h in chen_data['hours']:
        hour_counts[h] += 1
    
    for hour in sorted(hour_counts.keys()):
        count = hour_counts[hour]
        pct = count / len(chen_data['commits']) * 100
        bar = '█' * int(pct / 2)
        unusual = " ⚠️ UNUSUAL" if hour in unusual_hours else ""
        print(f"  {hour:02d}:00 - {count:4d} commits ({pct:5.1f}%) {bar}{unusual}")
    
    unusual = sum(1 for h in chen_data['hours'] if h in unusual_hours)
    unusual_ratio = unusual / len(chen_data['commits'])
    print(f"\nUnusual hours (2-6 AM): {unusual} commits ({unusual_ratio*100:.1f}%)")
    print(f"Risk score: {min(unusual_ratio * 2, 1.0):.2f}")
else:
    print("Yuanyuan Chen not found in contributors")

# Save report
report = {
    'total_commits': len(commits),
    'total_contributors': len(contributors),
    'anomalies': sorted(anomalies, key=lambda x: x['risk_score'], reverse=True)[:20]
}

report_file = output_dir / f"quick_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
with open(report_file, 'w') as f:
    json.dump(report, f, indent=2)

print(f"\n✅ Report saved: {report_file}")
