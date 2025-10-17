#!/usr/bin/env python3
"""
Real-World Validation for SPR{K}3
Tests on actual repositories
"""
import os
import sys
import json
import subprocess
from datetime import datetime

def test_repository(repo_url, repo_name):
    """Clone and test a repository"""
    print(f"\n{'='*60}")
    print(f"Testing: {repo_name}")
    print(f"{'='*60}")
    
    # Clone if not exists
    if not os.path.exists(f"test_repos/{repo_name}"):
        os.makedirs("test_repos", exist_ok=True)
        print(f"Cloning {repo_name}...")
        subprocess.run([
            "git", "clone", "--depth", "1", 
            repo_url, f"test_repos/{repo_name}"
        ], capture_output=True)
    
    # Run SPR{K}3
    print(f"Running SPR{K}3 analysis...")
    result = subprocess.run([
        "python", "sprk3_engine.py", f"test_repos/{repo_name}"
    ], capture_output=True, text=True)
    
    # Parse results
    output = result.stdout
    print(output)
    
    # Save results
    with open(f"test_results_{repo_name}.txt", "w") as f:
        f.write(output)
    
    return output

# Test popular repositories
test_cases = [
    ("https://github.com/numpy/numpy.git", "numpy"),
    ("https://github.com/scikit-learn/scikit-learn.git", "scikit-learn"),
    ("https://github.com/tensorflow/tensorflow.git", "tensorflow"),
]

print("🔬 SPR{K}3 Real-World Validation")
print(f"Started: {datetime.now()}")

results = {}
for repo_url, repo_name in test_cases:
    try:
        output = test_repository(repo_url, repo_name)
        # Extract summary
        if "Files Scanned:" in output:
            files = output.split("Files Scanned:")[1].split("\n")[0].strip()
            patterns = output.split("Patterns Detected:")[1].split("\n")[0].strip() if "Patterns Detected:" in output else "0"
            threats = output.split("Threats Found:")[1].split("\n")[0].strip() if "Threats Found:" in output else "0"
            results[repo_name] = {
                "files": files,
                "patterns": patterns,
                "threats": threats
            }
    except Exception as e:
        print(f"Error testing {repo_name}: {e}")
        results[repo_name] = {"error": str(e)}

# Summary
print("\n" + "="*60)
print("📊 VALIDATION SUMMARY")
print("="*60)
for repo, data in results.items():
    if "error" not in data:
        print(f"{repo:20} Files: {data['files']:6} Patterns: {data['patterns']:6} Threats: {data['threats']:6}")
    else:
        print(f"{repo:20} ERROR: {data['error']}")

print("\n✅ Validation Complete!")
