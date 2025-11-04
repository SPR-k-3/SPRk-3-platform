#!/usr/bin/env python3
"""
SPR{K}3 Integrated Behavioral Analysis
Combines Temporal Anomaly Detection + Code Complexity Analysis

Provides complete behavioral profile:
- WHEN: Commit timing patterns
- HOW FAST: Velocity anomalies
- HOW COMPLEX: Code quality metrics
- SUSPICIOUS: Combined risk scoring
"""

import subprocess
import json
import sys
from pathlib import Path
from datetime import datetime


def run_temporal_analysis(repo):
    """Run temporal anomaly detector"""
    print("\n" + "="*80)
    print("STEP 1: TEMPORAL ANALYSIS - Behavioral Pattern Detection")
    print("="*80)
    
    cmd = ['python3', 'sprk3_temporal_anomaly_detector.py', repo]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    print(result.stdout)
    
    if result.returncode != 0:
        print(f"[!] Temporal analysis failed: {result.stderr}")
        return None
    
    # Find latest report
    reports = sorted(Path("temporal_analysis").glob("*.json"))
    if reports:
        with open(reports[-1]) as f:
            return json.load(f)
    
    return None


def run_complexity_analysis(repo):
    """Run complexity analyzer"""
    print("\n" + "="*80)
    print("STEP 2: COMPLEXITY ANALYSIS - Code Quality Assessment")
    print("="*80)
    
    cmd = ['python3', 'complexity_analyzer.py', repo]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    print(result.stdout)
    
    if result.returncode != 0:
        print(f"[!] Complexity analysis failed: {result.stderr}")
        return None
    
    # Find latest report
    reports = sorted(Path("complexity_analysis").glob("*.json"))
    if reports:
        with open(reports[-1]) as f:
            return json.load(f)
    
    return None


def generate_integrated_report(temporal_report, complexity_report):
    """Generate integrated behavioral analysis"""
    print("\n" + "="*80)
    print("STEP 3: INTEGRATED ANALYSIS - Complete Behavioral Profile")
    print("="*80)
    
    if not temporal_report or not complexity_report:
        print("[!] Missing reports for integration")
        return
    
    # Extract temporal data
    temporal_contributors = temporal_report.get('contributor_profiles', {})
    temporal_anomalies = temporal_report.get('anomalies', [])
    
    # Extract complexity data
    complexity_hotspots = complexity_report.get('hotspots', [])
    technical_debt = complexity_report.get('technical_debt_score', 0)
    
    print(f"\n📊 INTEGRATED BEHAVIORAL SUMMARY:")
    print(f"   Total Contributors: {len(temporal_contributors)}")
    print(f"   Temporal Anomalies: {len(temporal_anomalies)}")
    print(f"   Complexity Hotspots: {len(complexity_hotspots)}")
    print(f"   Technical Debt: {technical_debt:.1f}/100")
    
    # Find contributors with both temporal and complexity issues
    print(f"\n🔍 CROSS-ANALYSIS:")
    
    # Map complexity hotspots to contributors (simplified)
    hotspot_files = {h['file'] for h in complexity_hotspots}
    
    print(f"\n   High-Risk Patterns Detected:")
    print(f"   • {len(temporal_anomalies)} timing/velocity anomalies")
    print(f"   • {len(complexity_hotspots)} high-complexity functions")
    print(f"   • {len(hotspot_files)} files with complexity issues")
    
    # Analyze correlation
    print(f"\n💡 BEHAVIORAL INSIGHTS:")
    
    if technical_debt > 60:
        print(f"   🔴 CRITICAL: High technical debt ({technical_debt:.0f}/100)")
        print(f"      Recommendation: Major refactoring needed")
    elif technical_debt > 40:
        print(f"   ⚠️  WARNING: Moderate technical debt ({technical_debt:.0f}/100)")
        print(f"      Recommendation: Prioritize cleanup")
    else:
        print(f"   ✅ GOOD: Low technical debt ({technical_debt:.0f}/100)")
    
    if len(temporal_anomalies) > 20:
        print(f"   ⚠️  HIGH: {len(temporal_anomalies)} temporal anomalies detected")
        print(f"      Recommendation: Review contributor behavior patterns")
    
    # Show top complexity hotspots
    if complexity_hotspots:
        print(f"\n🔥 TOP COMPLEXITY HOTSPOTS:")
        for i, hotspot in enumerate(complexity_hotspots[:5], 1):
            print(f"\n   {i}. {hotspot['function']} ({hotspot['file']})")
            print(f"      Complexity: {hotspot['cyclomatic_complexity']} (cyclomatic)")
            print(f"      Nesting: {hotspot['nesting_depth']} levels")
            
            if hotspot.get('obfuscation_score', 0) > 0.5:
                print(f"      ⚠️  Obfuscation Score: {hotspot['obfuscation_score']:.2f}")
            
            if hotspot.get('issues'):
                print(f"      Issues: {', '.join(hotspot['issues'][:2])}")
    
    # Show temporal high-risk contributors
    high_risk_temporal = [
        name for name, prof in temporal_contributors.items()
        if prof.get('risk_score', 0) >= 0.6
    ]
    
    if high_risk_temporal:
        print(f"\n⚠️  HIGH-RISK CONTRIBUTORS (Temporal):")
        for name in high_risk_temporal[:5]:
            prof = temporal_contributors[name]
            print(f"\n   {name}:")
            print(f"      Risk Score: {prof['risk_score']:.2f}")
            print(f"      Velocity Spikes: {prof.get('velocity_spikes', 0)}")
            print(f"      Timing Anomalies: {prof.get('timing_anomalies', 0)}")
            print(f"      Total Commits: {prof['total_commits']}")
    
    # Recommendations
    print(f"\n💡 RECOMMENDATIONS:")
    
    print(f"\n   1. CODE QUALITY:")
    if technical_debt > 50:
        print(f"      • Refactor top {min(10, len(complexity_hotspots))} complexity hotspots")
        print(f"      • Establish complexity limits (cyclomatic < 15)")
        print(f"      • Add automated complexity checks to CI/CD")
    else:
        print(f"      • Continue maintaining current quality standards")
    
    print(f"\n   2. BEHAVIORAL MONITORING:")
    if high_risk_temporal:
        print(f"      • Review code from {len(high_risk_temporal)} high-risk contributors")
        print(f"      • Monitor for unusual commit patterns")
        print(f"      • Consider additional code review for off-hours commits")
    else:
        print(f"      • No high-risk behavioral patterns detected")
    
    print(f"\n   3. SECURITY:")
    obfuscated_count = sum(1 for h in complexity_hotspots if h.get('obfuscation_score', 0) > 0.5)
    if obfuscated_count > 0:
        print(f"      • Investigate {obfuscated_count} potentially obfuscated functions")
        print(f"      • May indicate malware or intentional complexity")
        print(f"      • Recommend security audit")
    else:
        print(f"      • No obfuscation patterns detected")
    
    print("\n" + "="*80)
    
    # Save integrated report
    integrated = {
        'analysis_date': datetime.now().isoformat(),
        'temporal_analysis': {
            'total_contributors': len(temporal_contributors),
            'anomalies': len(temporal_anomalies),
            'high_risk_contributors': len(high_risk_temporal)
        },
        'complexity_analysis': {
            'total_functions': complexity_report.get('total_functions', 0),
            'technical_debt': technical_debt,
            'hotspots': len(complexity_hotspots)
        },
        'integrated_risk_score': calculate_integrated_risk(
            temporal_report, complexity_report
        )
    }
    
    report_file = f"integrated_behavioral_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(integrated, f, indent=2)
    
    print(f"\n[+] Integrated report saved: {report_file}\n")


def calculate_integrated_risk(temporal_report, complexity_report):
    """Calculate combined risk score"""
    risk = 0.0
    
    # Temporal risk
    anomalies = len(temporal_report.get('anomalies', []))
    if anomalies > 0:
        risk += min(anomalies / 50, 0.3)  # Max 0.3 from anomalies
    
    # Complexity risk
    debt = complexity_report.get('technical_debt_score', 0)
    risk += (debt / 100) * 0.4  # Max 0.4 from technical debt
    
    # Obfuscation risk
    hotspots = complexity_report.get('hotspots', [])
    obfuscated = sum(1 for h in hotspots if h.get('obfuscation_score', 0) > 0.5)
    if obfuscated > 0:
        risk += min(obfuscated / 10, 0.3)  # Max 0.3 from obfuscation
    
    return min(1.0, risk)


def main():
    """Main execution"""
    if len(sys.argv) < 2:
        print("""
SPR{K}3 Integrated Behavioral Analysis

Usage:
    python3 integrated_behavioral_analysis.py <repository_path>

Example:
    python3 integrated_behavioral_analysis.py ~/pytorch_repo

What it does:
    1. Runs Temporal Anomaly Detection (velocity, timing)
    2. Runs Code Complexity Analysis (quality, obfuscation)
    3. Generates integrated behavioral profile

Output:
    - Temporal analysis report (JSON)
    - Complexity analysis report (JSON)
    - Integrated behavioral report (JSON)
        """)
        sys.exit(1)
    
    repo = sys.argv[1]
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║  SPR{K}3 INTEGRATED BEHAVIORAL ANALYSIS                      ║
    ║  Temporal + Complexity = Complete Behavioral Profile          ║
    ║                                                               ║
    ║  Author: Dan Aridor - SPR{K}3 Security Research Team         ║
    ║  Patent: US Provisional (October 8, 2025)                    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Run both analyses
    temporal_report = run_temporal_analysis(repo)
    complexity_report = run_complexity_analysis(repo)
    
    # Generate integrated report
    generate_integrated_report(temporal_report, complexity_report)
    
    print("\n[+] Integrated behavioral analysis complete!\n")


if __name__ == "__main__":
    main()
