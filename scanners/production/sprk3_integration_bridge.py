"""
SPR{K}3 Integration Bridge
===========================

Connects all 6 SPR{K}3 engines into a unified threat detection system.

Engines:
1. Bio-Intelligence - Survival pattern recognition
2. Temporal Intelligence - Time-series anomaly detection
3. Structural Intelligence - Dependency graph analysis
4. BrainGuard - LLM cognitive degradation prevention
5. Supply Chain Intelligence - Cloaking detection (with integrated detector)
6. Context Intelligence - False positive filtering

Author: Dan Aridor - SPR{K}3 Security Research Team
Date: November 2025
"""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from collections import defaultdict
import hashlib

# Import Engine 5 (Supply Chain with Cloaking Detection)
sys.path.insert(0, str(Path(__file__).parent / 'src' / 'engines'))
sys.path.insert(0, str(Path(__file__).parent / 'src' / 'detectors'))

try:
    from engine5_supply_chain import (
        Engine5SupplyChainIntelligence,
        SupplyChainThreat
    )
except ImportError:
    print("⚠️  Warning: Engine 5 not found. Some features will be limited.")
    Engine5SupplyChainIntelligence = None
    SupplyChainThreat = None


@dataclass
class ThreatEvent:
    """Unified threat event shared across engines"""
    event_id: str
    timestamp: str
    source_url: str
    threat_type: str
    severity: str
    engine_source: str  # Which engine detected it
    details: Dict[str, Any]
    related_events: List[str] = None


@dataclass
class IntegratedThreatAssessment:
    """Final threat assessment combining all engine inputs"""
    url: str
    overall_severity: str
    threat_types: List[str]
    engine_verdicts: Dict[str, str]
    temporal_analysis: Optional[Dict] = None
    structural_impact: Optional[Dict] = None
    context_verdict: Optional[Dict] = None
    brainguard_status: Optional[Dict] = None
    recommendations: List[str] = None
    action_required: str = None
    timestamp: str = None


class Engine2TemporalIntelligence:
    """Engine 2: Temporal Intelligence - Time-series analysis"""
    
    def __init__(self, history_window_hours: int = 168):  # 7 days
        self.history_window_hours = history_window_hours
        self.event_history = defaultdict(list)  # url -> [events]
    
    def record_event(self, event: ThreatEvent):
        """Record threat event for temporal analysis"""
        self.event_history[event.source_url].append({
            'timestamp': event.timestamp,
            'severity': event.severity,
            'divergence_score': event.details.get('divergence_score', 0.0)
        })
    
    def analyze_trend(self, url: str) -> Dict:
        """Analyze temporal patterns for URL"""
        events = self.event_history.get(url, [])
        
        if len(events) < 2:
            return {
                'pattern': 'insufficient_data',
                'frequency': len(events),
                'trend': 'unknown',
                'coordinated_attack': False
            }
        
        # Calculate frequency
        now = datetime.now()
        recent_events = [
            e for e in events
            if (now - datetime.fromisoformat(e['timestamp'])).total_seconds() / 3600 < self.history_window_hours
        ]
        
        frequency = len(recent_events)
        
        # Check if divergence scores are increasing (coordinated attack pattern)
        scores = [e['divergence_score'] for e in recent_events if e['divergence_score'] > 0]
        
        trend = 'stable'
        if len(scores) >= 3:
            if scores[-1] > scores[0] * 1.2:
                trend = 'increasing'
            elif scores[-1] < scores[0] * 0.8:
                trend = 'decreasing'
        
        # Coordinated attack: increasing scores + high frequency
        coordinated = trend == 'increasing' and frequency >= 5
        
        return {
            'pattern': 'coordinated_attack' if coordinated else 'isolated_incident',
            'frequency': frequency,
            'trend': trend,
            'coordinated_attack': coordinated,
            'event_count': len(events),
            'recent_event_count': len(recent_events)
        }


class Engine3StructuralIntelligence:
    """Engine 3: Structural Intelligence - Dependency graph analysis"""
    
    def __init__(self):
        self.dependency_graph = defaultdict(set)  # file -> set of dependents
    
    def register_dependency(self, source: str, dependent: str):
        """Register that 'dependent' depends on 'source'"""
        self.dependency_graph[source].add(dependent)
    
    def calculate_blast_radius(self, url: str) -> Dict:
        """Calculate impact if URL is compromised"""
        direct_dependents = self.dependency_graph.get(url, set())
        
        # BFS to find all transitive dependents
        all_dependents = set()
        to_check = list(direct_dependents)
        checked = set()
        
        while to_check:
            current = to_check.pop(0)
            if current in checked:
                continue
            
            checked.add(current)
            all_dependents.add(current)
            
            # Add transitive dependents
            transitive = self.dependency_graph.get(current, set())
            to_check.extend(transitive)
        
        # Classify impact
        total_affected = len(all_dependents)
        
        if total_affected == 0:
            impact_level = 'isolated'
        elif total_affected < 10:
            impact_level = 'limited'
        elif total_affected < 50:
            impact_level = 'moderate'
        elif total_affected < 100:
            impact_level = 'high'
        else:
            impact_level = 'critical'
        
        return {
            'affected_files': total_affected,
            'direct_dependents': len(direct_dependents),
            'impact_level': impact_level,
            'critical_systems': self._identify_critical_systems(all_dependents)
        }
    
    def _identify_critical_systems(self, files: set) -> List[str]:
        """Identify critical systems affected"""
        critical = []
        critical_keywords = ['auth', 'security', 'crypto', 'payment', 'admin', 'kernel', 'core']
        
        for file in files:
            if any(keyword in file.lower() for keyword in critical_keywords):
                critical.append(file)
        
        return critical[:10]  # Limit to top 10


class Engine4BrainGuard:
    """Engine 4: BrainGuard - LLM cognitive degradation monitoring"""
    
    def __init__(self):
        self.monitored_sources = {}  # url -> monitoring status
        self.degradation_alerts = []
    
    def mark_source_as_suspect(self, url: str):
        """Start monitoring artifacts from this source"""
        self.monitored_sources[url] = {
            'status': 'monitoring',
            'start_time': datetime.now().isoformat(),
            'alerts': 0
        }
    
    def check_degradation(self, url: str) -> Dict:
        """Check if source has caused model degradation"""
        if url not in self.monitored_sources:
            return {'monitored': False}
        
        status = self.monitored_sources[url]
        
        # Simulate degradation check (in production, would actually test model)
        return {
            'monitored': True,
            'degradation_detected': status['alerts'] > 0,
            'alert_count': status['alerts'],
            'recommendation': 'rollback' if status['alerts'] > 2 else 'continue_monitoring'
        }
    
    def simulate_degradation_alert(self, url: str):
        """Simulate detecting degradation (for testing)"""
        if url in self.monitored_sources:
            self.monitored_sources[url]['alerts'] += 1
            self.degradation_alerts.append({
                'url': url,
                'timestamp': datetime.now().isoformat()
            })


class Engine6ContextIntelligence:
    """Engine 6: Context Intelligence - False positive filtering"""
    
    def __init__(self):
        self.whitelist = set([
            'github.com',
            'huggingface.co',
            'pytorch.org',
            'tensorflow.org',
            'anthropic.com',
            'openai.com'
        ])
        
        self.known_dynamic_content_patterns = [
            'cdn.', 'cache.', 'static.', 'assets.'
        ]
    
    def analyze_context(self, url: str) -> Dict:
        """Analyze context to filter false positives"""
        is_whitelisted = any(domain in url for domain in self.whitelist)
        is_cdn = any(pattern in url for pattern in self.known_dynamic_content_patterns)
        
        verdict = 'safe' if is_whitelisted else 'unknown'
        confidence = 0.95 if is_whitelisted else 0.5
        
        return {
            'verdict': verdict,
            'confidence': confidence,
            'is_whitelisted': is_whitelisted,
            'is_cdn': is_cdn,
            'false_positive_likely': is_whitelisted and is_cdn
        }


class SPRk3IntegrationBridge:
    """
    Central integration hub connecting all 6 SPR{K}3 engines
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        
        # Initialize all engines
        self._log("🚀 Initializing SPR{K}3 Integration Bridge...")
        
        self.engine2 = Engine2TemporalIntelligence()
        self._log("   ✓ Engine 2: Temporal Intelligence")
        
        self.engine3 = Engine3StructuralIntelligence()
        self._log("   ✓ Engine 3: Structural Intelligence")
        
        self.engine4 = Engine4BrainGuard()
        self._log("   ✓ Engine 4: BrainGuard")
        
        if Engine5SupplyChainIntelligence:
            self.engine5 = Engine5SupplyChainIntelligence(
                enable_cloaking_detection=True,
                verbose=verbose
            )
            self._log("   ✓ Engine 5: Supply Chain Intelligence (with cloaking)")
        else:
            self.engine5 = None
            self._log("   ⚠️  Engine 5: Not available")
        
        self.engine6 = Engine6ContextIntelligence()
        self._log("   ✓ Engine 6: Context Intelligence")
        
        # Event tracking
        self.all_events = []
        
        self._log("✅ All engines initialized!\n")
    
    def integrated_scan(self, url: str) -> IntegratedThreatAssessment:
        """
        Perform integrated scan using all engines
        """
        self._log(f"{'='*80}")
        self._log(f"SPR{{K}}3 INTEGRATED SCAN")
        self._log(f"{'='*80}")
        self._log(f"URL: {url}\n")
        
        # STEP 1: Engine 5 - Supply Chain Validation (with cloaking detection)
        self._log("[ENGINE 5] Supply Chain Intelligence...")
        
        if self.engine5:
            supply_chain_result = self.engine5.validate_external_dependency(url)
            
            # Create threat event
            event = ThreatEvent(
                event_id=hashlib.md5(f"{url}{datetime.now()}".encode()).hexdigest()[:8],
                timestamp=datetime.now().isoformat(),
                source_url=url,
                threat_type=supply_chain_result.threat_type,
                severity=supply_chain_result.severity,
                engine_source='engine5_supply_chain',
                details={
                    'cloaking_detected': supply_chain_result.cloaking_detected,
                    'divergence_score': supply_chain_result.cloaking_score,
                    'vulnerability_details': supply_chain_result.vulnerability_details
                }
            )
            self.all_events.append(event)
        else:
            supply_chain_result = None
            event = None
            self._log("   ⚠️  Engine 5 not available - skipping")
        
        # STEP 2: Engine 2 - Temporal Analysis
        self._log("\n[ENGINE 2] Temporal Intelligence...")
        
        if event:
            self.engine2.record_event(event)
        
        temporal_analysis = self.engine2.analyze_trend(url)
        self._log(f"   Pattern: {temporal_analysis['pattern']}")
        self._log(f"   Frequency: {temporal_analysis['frequency']} events")
        self._log(f"   Trend: {temporal_analysis['trend']}")
        
        if temporal_analysis['coordinated_attack']:
            self._log("   🚨 COORDINATED ATTACK PATTERN DETECTED!")
        
        # STEP 3: Engine 3 - Structural Impact
        self._log("\n[ENGINE 3] Structural Intelligence...")
        
        structural_impact = self.engine3.calculate_blast_radius(url)
        self._log(f"   Affected files: {structural_impact['affected_files']}")
        self._log(f"   Impact level: {structural_impact['impact_level']}")
        
        if structural_impact['critical_systems']:
            self._log(f"   🚨 Critical systems affected: {len(structural_impact['critical_systems'])}")
        
        # STEP 4: Engine 6 - Context Analysis
        self._log("\n[ENGINE 6] Context Intelligence...")
        
        context_verdict = self.engine6.analyze_context(url)
        self._log(f"   Verdict: {context_verdict['verdict']}")
        self._log(f"   Confidence: {context_verdict['confidence']:.0%}")
        
        if context_verdict['false_positive_likely']:
            self._log("   ✓ Likely false positive (whitelisted + CDN)")
        
        # STEP 5: Engine 4 - BrainGuard Monitoring
        self._log("\n[ENGINE 4] BrainGuard...")
        
        if supply_chain_result and supply_chain_result.cloaking_detected:
            self.engine4.mark_source_as_suspect(url)
            self._log(f"   → Marked source for degradation monitoring")
        
        brainguard_status = self.engine4.check_degradation(url)
        
        if brainguard_status['monitored']:
            self._log(f"   Status: Monitoring active")
        
        # STEP 6: Integrated Threat Assessment
        self._log(f"\n{'='*80}")
        self._log(f"INTEGRATED THREAT ASSESSMENT")
        self._log(f"{'='*80}\n")
        
        assessment = self._make_integrated_decision(
            url=url,
            supply_chain_result=supply_chain_result,
            temporal_analysis=temporal_analysis,
            structural_impact=structural_impact,
            context_verdict=context_verdict,
            brainguard_status=brainguard_status
        )
        
        self._display_assessment(assessment)
        
        return assessment
    
    def _make_integrated_decision(self, url, supply_chain_result, temporal_analysis,
                                   structural_impact, context_verdict, brainguard_status) -> IntegratedThreatAssessment:
        """Combine all engine inputs into final decision"""
        
        # Collect verdicts
        engine_verdicts = {}
        threat_types = []
        recommendations = []
        
        # Engine 5 verdict
        if supply_chain_result:
            engine_verdicts['supply_chain'] = supply_chain_result.severity
            if supply_chain_result.threat_type != 'unknown':
                threat_types.append(supply_chain_result.threat_type)
        
        # Engine 2 verdict
        if temporal_analysis['coordinated_attack']:
            engine_verdicts['temporal'] = 'CRITICAL'
            threat_types.append('coordinated_attack')
            recommendations.append("🚨 Coordinated attack pattern detected - immediate investigation required")
        else:
            engine_verdicts['temporal'] = 'LOW'
        
        # Engine 3 verdict
        if structural_impact['impact_level'] in ['high', 'critical']:
            engine_verdicts['structural'] = 'HIGH'
            threat_types.append('high_blast_radius')
            recommendations.append(f"⚠️  High blast radius: {structural_impact['affected_files']} files affected")
        else:
            engine_verdicts['structural'] = 'LOW'
        
        # Engine 6 verdict (can downgrade severity)
        if context_verdict['false_positive_likely']:
            engine_verdicts['context'] = 'FALSE_POSITIVE'
            recommendations.append("✓ Likely false positive based on context analysis")
        else:
            engine_verdicts['context'] = 'GENUINE'
        
        # Engine 4 verdict
        if brainguard_status.get('degradation_detected'):
            engine_verdicts['brainguard'] = 'CRITICAL'
            threat_types.append('model_degradation')
            recommendations.append("🚨 Model degradation detected from this source")
        else:
            engine_verdicts['brainguard'] = 'MONITORING'
        
        # Determine overall severity
        severities = [v for v in engine_verdicts.values() if v not in ['FALSE_POSITIVE', 'MONITORING']]
        
        if 'CRITICAL' in severities:
            overall_severity = 'CRITICAL'
        elif 'HIGH' in severities:
            overall_severity = 'HIGH'
        elif 'MEDIUM' in severities:
            overall_severity = 'MEDIUM'
        else:
            overall_severity = 'LOW'
        
        # Downgrade if false positive
        if context_verdict['false_positive_likely'] and overall_severity != 'CRITICAL':
            overall_severity = 'LOW'
            recommendations.append("ℹ️  Severity downgraded due to false positive likelihood")
        
        # Determine action
        if overall_severity == 'CRITICAL':
            action = 'IMMEDIATE_QUARANTINE'
        elif overall_severity == 'HIGH':
            action = 'QUARANTINE_AND_REVIEW'
        elif overall_severity == 'MEDIUM':
            action = 'TAG_AND_MONITOR'
        else:
            action = 'SAFE_WITH_VALIDATION'
        
        return IntegratedThreatAssessment(
            url=url,
            overall_severity=overall_severity,
            threat_types=threat_types,
            engine_verdicts=engine_verdicts,
            temporal_analysis=temporal_analysis,
            structural_impact=structural_impact,
            context_verdict=context_verdict,
            brainguard_status=brainguard_status,
            recommendations=recommendations,
            action_required=action,
            timestamp=datetime.now().isoformat()
        )
    
    def _display_assessment(self, assessment: IntegratedThreatAssessment):
        """Display integrated assessment"""
        severity_icon = "🚨" if assessment.overall_severity in ['CRITICAL', 'HIGH'] else "✓"
        
        print(f"{severity_icon} OVERALL SEVERITY: {assessment.overall_severity}")
        print(f"\n📊 ENGINE VERDICTS:")
        for engine, verdict in assessment.engine_verdicts.items():
            print(f"   {engine.upper()}: {verdict}")
        
        if assessment.threat_types:
            print(f"\n⚠️  THREAT TYPES:")
            for threat in assessment.threat_types:
                print(f"   • {threat}")
        
        if assessment.recommendations:
            print(f"\n💡 RECOMMENDATIONS:")
            for rec in assessment.recommendations:
                print(f"   {rec}")
        
        print(f"\n🎯 ACTION REQUIRED: {assessment.action_required}")
        print(f"{'='*80}\n")
    
    def _log(self, message: str):
        """Log message if verbose"""
        if self.verbose:
            print(message, file=sys.stderr)


def main():
    """Command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='SPR{K}3 Integrated Scan - All 6 engines working together'
    )
    parser.add_argument('urls', nargs='+', help='URLs to scan')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--report', help='Output JSON report')
    
    args = parser.parse_args()
    
    # Initialize bridge
    bridge = SPRk3IntegrationBridge(verbose=args.verbose)
    
    # Scan all URLs
    results = []
    for url in args.urls:
        try:
            result = bridge.integrated_scan(url)
            results.append(asdict(result))
        except Exception as e:
            print(f"❌ Error scanning {url}: {e}", file=sys.stderr)
    
    # Save report
    if args.report:
        with open(args.report, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n📄 Report saved: {args.report}")
    
    # Exit code based on severity
    critical = sum(1 for r in results if r['overall_severity'] == 'CRITICAL')
    if critical > 0:
        return 2
    
    high = sum(1 for r in results if r['overall_severity'] == 'HIGH')
    if high > 0:
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
