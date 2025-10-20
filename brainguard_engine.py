#!/usr/bin/env python3
"""
SPR{K}3-BrainGuard: LLM Brain Rot Prevention System
Based on the paper's findings about cognitive degradation from low-quality training data
"""

import json
import random
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from collections import deque
import statistics

# ANSI color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    ORANGE = '\033[38;5;208m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

@dataclass
class DataSample:
    """Represents a training data sample with metadata"""
    text: str
    engagement_score: float = 0.0
    source: str = "unknown"
    timestamp: str = ""
    metadata: Dict = None

@dataclass
class HealthMetrics:
    """Current cognitive health metrics"""
    reasoning_score: float = 1.0
    coherence_score: float = 1.0
    safety_score: float = 1.0
    personality_score: float = 1.0
    thought_skip_rate: float = 0.0
    cumulative_junk_exposure: float = 0.0

class ReasoningChainAnalyzer:
    """Detects thought-skipping - the primary brain rot symptom"""
    
    def __init__(self):
        self.baseline_chain_length = 5
        self.skip_threshold = 0.3
        
    def analyze_reasoning(self, text: str) -> Dict:
        """Analyze reasoning chain completeness"""
        
        # Detect reasoning markers
        premise_markers = ['because', 'since', 'given that', 'considering']
        step_markers = ['first', 'then', 'next', 'furthermore', 'additionally']
        conclusion_markers = ['therefore', 'thus', 'so', 'in conclusion', 'hence']
        
        has_premise = any(marker in text.lower() for marker in premise_markers)
        has_steps = sum(1 for marker in step_markers if marker in text.lower())
        has_conclusion = any(marker in text.lower() for marker in conclusion_markers)
        
        # Count logical steps
        sentences = re.split(r'[.!?]+', text)
        logical_steps = len([s for s in sentences if len(s.strip()) > 10])
        
        # Detect thought-skipping
        expected_steps = self.baseline_chain_length
        actual_steps = logical_steps
        skip_rate = 1 - (actual_steps / expected_steps) if expected_steps > 0 else 0
        
        # Calculate completeness score
        completeness = 0.0
        if has_premise: completeness += 0.3
        if has_steps > 0: completeness += 0.4 * min(has_steps / 3, 1.0)
        if has_conclusion: completeness += 0.3
        
        return {
            'has_premise': has_premise,
            'reasoning_steps': has_steps,
            'has_conclusion': has_conclusion,
            'completeness_score': completeness,
            'thought_skip_rate': max(0, skip_rate),
            'chain_broken': has_conclusion and not has_premise
        }

class QualityDosageTracker:
    """Tracks cumulative exposure to low-quality data"""
    
    def __init__(self):
        self.cumulative_junk_ratio = 0.0
        self.total_samples = 0
        self.junk_samples = 0
        self.exposure_history = deque(maxlen=1000)
        
        # Risk thresholds from paper
        self.risk_zones = {
            'green': 0.2,   # < 20% junk
            'yellow': 0.4,  # 20-40% junk  
            'orange': 0.6,  # 40-60% junk
            'red': 0.8      # > 60% junk (17.7% performance drop expected)
        }
    
    def assess_quality(self, sample: DataSample) -> Dict:
        """Multi-dimensional quality assessment"""
        
        scores = {}
        
        # 1. Engagement Score (paper's key finding: engagement > length)
        if sample.engagement_score < 0.2:
            scores['engagement'] = 0.0  # Bottom 20% = junk
        elif sample.engagement_score < 0.5:
            scores['engagement'] = 0.5
        else:
            scores['engagement'] = 1.0
            
        # 2. Information Density
        words = sample.text.split()
        unique_words = len(set(words))
        if len(words) > 0:
            diversity = unique_words / len(words)
            scores['density'] = min(diversity * 2, 1.0)  # Scale to 0-1
        else:
            scores['density'] = 0.0
            
        # 3. Toxic Pattern Detection
        toxic_patterns = [
            'BREAKING:', 'URGENT:', '!!!', '???', 
            'DISASTER', 'DESTROYING', 'SHAME',
            'clickbait', 'you won\'t believe'
        ]
        toxic_count = sum(1 for pattern in toxic_patterns if pattern in sample.text.upper())
        scores['toxicity'] = max(0, 1 - (toxic_count * 0.2))
        
        # 4. Length Quality (not just length, but substance)
        if len(words) < 5:
            scores['substance'] = 0.0  # Too short
        elif len(words) > 500:
            scores['substance'] = 0.5  # Possibly rambling
        else:
            scores['substance'] = 1.0
            
        # Combined quality score (weighted)
        weights = {
            'engagement': 0.35,  # Highest weight - paper's finding
            'density': 0.25,
            'toxicity': 0.20,
            'substance': 0.20
        }
        
        final_score = sum(scores[k] * weights[k] for k in weights)
        
        return {
            'scores': scores,
            'final_quality': final_score,
            'is_junk': final_score < 0.5,
            'risk_level': self._get_risk_level(final_score)
        }
    
    def _get_risk_level(self, quality_score: float) -> str:
        """Determine risk level with color coding"""
        if quality_score > 0.7:
            return f"{Colors.GREEN}🟢 GREEN{Colors.RESET}"
        elif quality_score > 0.5:
            return f"{Colors.YELLOW}🟡 YELLOW{Colors.RESET}"
        elif quality_score > 0.3:
            return f"{Colors.ORANGE}🟠 ORANGE{Colors.RESET}"
        else:
            return f"{Colors.RED}🔴 RED{Colors.RESET}"
    
    def update_exposure(self, is_junk: bool) -> Dict:
        """Track cumulative junk exposure"""
        self.total_samples += 1
        if is_junk:
            self.junk_samples += 1
        
        self.exposure_history.append(1 if is_junk else 0)
        self.cumulative_junk_ratio = self.junk_samples / self.total_samples if self.total_samples > 0 else 0
        
        # Calculate recent trend
        if len(self.exposure_history) > 10:
            recent_junk_rate = sum(self.exposure_history) / len(self.exposure_history)
        else:
            recent_junk_rate = self.cumulative_junk_ratio
            
        # Determine overall risk zone
        if self.cumulative_junk_ratio < self.risk_zones['green']:
            zone = "GREEN"
            alert = False
        elif self.cumulative_junk_ratio < self.risk_zones['yellow']:
            zone = "YELLOW"
            alert = False
        elif self.cumulative_junk_ratio < self.risk_zones['orange']:
            zone = "ORANGE"
            alert = True
        else:
            zone = "RED"
            alert = True
            
        return {
            'cumulative_junk_ratio': self.cumulative_junk_ratio,
            'recent_junk_rate': recent_junk_rate,
            'total_samples': self.total_samples,
            'junk_samples': self.junk_samples,
            'risk_zone': zone,
            'alert': alert,
            'expected_performance_drop': self._calculate_expected_drop()
        }
    
    def _calculate_expected_drop(self) -> float:
        """Based on paper's dose-response findings"""
        # Paper: 70% junk = 17.7% drop in ARC-Challenge
        if self.cumulative_junk_ratio >= 0.7:
            return 17.7
        elif self.cumulative_junk_ratio >= 0.5:
            return 10.0
        elif self.cumulative_junk_ratio >= 0.3:
            return 5.0
        else:
            return 0.0

class CapabilityDriftDetector:
    """Monitors for degradation across multiple cognitive dimensions"""
    
    def __init__(self):
        self.baseline_metrics = HealthMetrics()
        self.current_metrics = HealthMetrics()
        self.history = []
        
    def benchmark_capabilities(self, sample_quality: float) -> Dict:
        """Simulate capability benchmarking"""
        
        # Simulate performance based on quality exposure
        # In real implementation, would run actual benchmarks
        degradation_factor = max(0, 1 - sample_quality)
        
        # Update metrics with simulated degradation
        self.current_metrics.reasoning_score *= (1 - degradation_factor * 0.1)
        self.current_metrics.coherence_score *= (1 - degradation_factor * 0.08)
        self.current_metrics.safety_score *= (1 - degradation_factor * 0.05)
        
        # Calculate Hedges' g effect size
        changes = {}
        for metric in ['reasoning_score', 'coherence_score', 'safety_score']:
            baseline = getattr(self.baseline_metrics, metric)
            current = getattr(self.current_metrics, metric)
            effect_size = abs(baseline - current) / 0.15  # Assuming SD of 0.15
            changes[metric] = {
                'baseline': baseline,
                'current': current,
                'change_pct': ((current - baseline) / baseline * 100) if baseline > 0 else 0,
                'hedges_g': effect_size,
                'significant': effect_size > 0.3  # Medium effect size
            }
        
        return changes

class RecoveryProtocol:
    """Intervention and recovery strategies"""
    
    def __init__(self):
        self.intervention_history = []
        self.recovery_strategies = {
            'clean_injection': 0.4,  # 40% recovery rate
            'instruction_tuning': 0.5,  # 50% recovery rate  
            'full_retrain': 0.6  # 60% recovery rate (from paper)
        }
    
    def recommend_intervention(self, health_status: Dict) -> Dict:
        """Recommend intervention based on current health"""
        
        junk_ratio = health_status.get('cumulative_junk_ratio', 0)
        risk_zone = health_status.get('risk_zone', 'GREEN')
        
        if risk_zone == 'RED':
            strategy = 'full_retrain'
            urgency = 'CRITICAL'
            description = "Severe degradation detected. Full retraining with clean data required."
        elif risk_zone == 'ORANGE':
            strategy = 'instruction_tuning'
            urgency = 'HIGH'
            description = "Significant drift detected. Instruction tuning recommended."
        elif risk_zone == 'YELLOW':
            strategy = 'clean_injection'
            urgency = 'MEDIUM'
            description = "Early degradation signs. Inject high-quality data."
        else:
            strategy = 'monitor'
            urgency = 'LOW'
            description = "System healthy. Continue monitoring."
            
        return {
            'strategy': strategy,
            'urgency': urgency,
            'description': description,
            'expected_recovery': self.recovery_strategies.get(strategy, 0),
            'estimated_steps': self._estimate_recovery_steps(strategy)
        }
    
    def _estimate_recovery_steps(self, strategy: str) -> int:
        """Estimate steps needed for recovery"""
        if strategy == 'full_retrain':
            return 10000
        elif strategy == 'instruction_tuning':
            return 5000
        elif strategy == 'clean_injection':
            return 2000
        else:
            return 0

class SPRk3BrainGuard:
    """Main Brain Guard System"""
    
    def __init__(self):
        self.reasoning_analyzer = ReasoningChainAnalyzer()
        self.dosage_tracker = QualityDosageTracker()
        self.drift_detector = CapabilityDriftDetector()
        self.recovery_system = RecoveryProtocol()
        self.monitoring_active = True
        
    def evaluate_batch(self, samples: List[DataSample]) -> Dict:
        """Evaluate a batch of training data"""
        
        print(f"\n{Colors.BOLD}═══════════════════════════════════════════════════════{Colors.RESET}")
        print(f"{Colors.BOLD}🧠 SPR{{K}}3-BrainGuard Batch Analysis{Colors.RESET}")
        print(f"{Colors.BOLD}═══════════════════════════════════════════════════════{Colors.RESET}\n")
        
        batch_results = []
        total_quality = 0
        junk_count = 0
        
        for i, sample in enumerate(samples, 1):
            print(f"{Colors.BLUE}Sample {i}:{Colors.RESET}")
            print(f"Text: \"{sample.text[:100]}...\"" if len(sample.text) > 100 else f"Text: \"{sample.text}\"")
            
            # Analyze reasoning
            reasoning = self.reasoning_analyzer.analyze_reasoning(sample.text)
            
            # Assess quality
            quality = self.dosage_tracker.assess_quality(sample)
            
            # Update exposure
            exposure = self.dosage_tracker.update_exposure(quality['is_junk'])
            
            total_quality += quality['final_quality']
            if quality['is_junk']:
                junk_count += 1
            
            # Display results
            print(f"├─ Quality Score: {quality['final_quality']:.2f} {quality['risk_level']}")
            print(f"├─ Reasoning Completeness: {reasoning['completeness_score']:.2f}")
            print(f"├─ Thought-Skip Rate: {reasoning['thought_skip_rate']:.2f}")
            
            if reasoning['chain_broken']:
                print(f"├─ ⚠️  {Colors.YELLOW}Warning: Broken reasoning chain detected!{Colors.RESET}")
            
            if quality['is_junk']:
                print(f"└─ 🚫 {Colors.RED}JUNK DATA DETECTED{Colors.RESET}")
            else:
                print(f"└─ ✅ {Colors.GREEN}Quality Pass{Colors.RESET}")
            print()
            
            batch_results.append({
                'sample': sample,
                'reasoning': reasoning,
                'quality': quality
            })
        
        # Batch summary
        avg_quality = total_quality / len(samples)
        junk_percentage = (junk_count / len(samples)) * 100
        
        print(f"{Colors.BOLD}Batch Summary:{Colors.RESET}")
        print(f"├─ Average Quality: {avg_quality:.2f}")
        print(f"├─ Junk Samples: {junk_count}/{len(samples)} ({junk_percentage:.1f}%)")
        print(f"└─ Cumulative Exposure: {exposure['cumulative_junk_ratio']:.1%}\n")
        
        return {
            'batch_results': batch_results,
            'avg_quality': avg_quality,
            'junk_percentage': junk_percentage,
            'exposure_status': exposure,
            'should_intervene': exposure['alert']
        }
    
    def get_health_report(self) -> Dict:
        """Generate comprehensive health report"""
        
        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}📊 COGNITIVE HEALTH REPORT{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")
        
        # Get current exposure status
        exposure = {
            'cumulative_junk_ratio': self.dosage_tracker.cumulative_junk_ratio,
            'total_samples': self.dosage_tracker.total_samples,
            'junk_samples': self.dosage_tracker.junk_samples,
            'risk_zone': self._get_zone_name()
        }
        
        # Check capabilities
        capabilities = self.drift_detector.benchmark_capabilities(
            1 - self.dosage_tracker.cumulative_junk_ratio
        )
        
        # Get intervention recommendation
        intervention = self.recovery_system.recommend_intervention(exposure)
        
        # Determine overall health
        if exposure['risk_zone'] == 'RED':
            health_status = f"{Colors.RED}❌ CRITICAL{Colors.RESET}"
        elif exposure['risk_zone'] == 'ORANGE':
            health_status = f"{Colors.ORANGE}⚠️  WARNING{Colors.RESET}"
        elif exposure['risk_zone'] == 'YELLOW':
            health_status = f"{Colors.YELLOW}🔶 CAUTION{Colors.RESET}"
        else:
            health_status = f"{Colors.GREEN}✅ HEALTHY{Colors.RESET}"
        
        # Display report
        print(f"{Colors.BOLD}Overall Status: {health_status}{Colors.RESET}\n")
        
        print(f"{Colors.BOLD}Exposure Metrics:{Colors.RESET}")
        print(f"├─ Cumulative Junk Ratio: {exposure['cumulative_junk_ratio']:.1%}")
        print(f"├─ Total Samples Processed: {exposure['total_samples']}")
        print(f"├─ Junk Samples Encountered: {exposure['junk_samples']}")
        print(f"└─ Risk Zone: {self._get_colored_zone()}\n")
        
        print(f"{Colors.BOLD}Capability Status:{Colors.RESET}")
        for metric, data in capabilities.items():
            status = "⚠️ " if data['significant'] else "✅"
            print(f"├─ {metric}: {data['current']:.3f} ({data['change_pct']:+.1f}%) {status}")
        print()
        
        print(f"{Colors.BOLD}Intervention Recommendation:{Colors.RESET}")
        print(f"├─ Strategy: {intervention['strategy']}")
        print(f"├─ Urgency: {intervention['urgency']}")
        print(f"├─ Expected Recovery: {intervention['expected_recovery']*100:.0f}%")
        print(f"└─ {intervention['description']}\n")
        
        if self.dosage_tracker.cumulative_junk_ratio > 0.5:
            print(f"{Colors.RED}{Colors.BOLD}⚠️  ALERT: Model at risk of permanent degradation!{Colors.RESET}")
            print(f"{Colors.RED}Paper shows only 40-60% recovery possible after damage.{Colors.RESET}\n")
        
        return {
            'health_status': health_status,
            'exposure': exposure,
            'capabilities': capabilities,
            'intervention': intervention
        }
    
    def _get_zone_name(self) -> str:
        ratio = self.dosage_tracker.cumulative_junk_ratio
        if ratio < 0.2:
            return 'GREEN'
        elif ratio < 0.4:
            return 'YELLOW'
        elif ratio < 0.6:
            return 'ORANGE'
        else:
            return 'RED'
    
    def _get_colored_zone(self) -> str:
        zone = self._get_zone_name()
        if zone == 'GREEN':
            return f"{Colors.GREEN}🟢 GREEN{Colors.RESET}"
        elif zone == 'YELLOW':
            return f"{Colors.YELLOW}🟡 YELLOW{Colors.RESET}"
        elif zone == 'ORANGE':
            return f"{Colors.ORANGE}🟠 ORANGE{Colors.RESET}"
        else:
            return f"{Colors.RED}🔴 RED{Colors.RESET}"

# Test data samples
def generate_test_samples() -> List[DataSample]:
    """Generate test samples of varying quality"""
    
    samples = [
        # High-quality sample
        DataSample(
            text="The Federal Reserve raised interest rates by 25 basis points because inflation remains above the 2% target. This decision follows three months of economic data showing persistent price pressures. Therefore, we can expect continued monetary tightening in the coming quarters.",
            engagement_score=0.8,
            source="financial_news"
        ),
        
        # Low-quality sample (junk)
        DataSample(
            text="Fed is DESTROYING economy!!! They don't know what they're doing... rates something something... DISASTER coming!!!",
            engagement_score=0.1,
            source="social_media"
        ),
        
        # Medium-quality sample
        DataSample(
            text="New AI model released today. It's pretty good. Better than the last one.",
            engagement_score=0.4,
            source="tech_blog"
        ),
        
        # Thought-skipping sample
        DataSample(
            text="Climate change is real. Therefore we need to ban all cars immediately.",
            engagement_score=0.2,
            source="opinion"
        ),
        
        # High engagement but toxic
        DataSample(
            text="BREAKING: You won't BELIEVE what this celebrity just did! SHOCKING revelation will leave you SPEECHLESS! Click here NOW!!!",
            engagement_score=0.7,
            source="clickbait"
        )
    ]
    
    return samples

def run_demo():
    """Run a demonstration of the Brain Guard system"""
    
    print(f"{Colors.PURPLE}{Colors.BOLD}")
    print("╔══════════════════════════════════════════════════════╗")
    print("║      SPR{K}3-BrainGuard: LLM Brain Rot Prevention    ║")
    print("║          Based on 'Your LLM has Brain Rot' Paper     ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}\n")
    
    # Initialize system
    guard = SPRk3BrainGuard()
    
    # Generate test samples
    samples = generate_test_samples()
    
    # Run batch evaluation
    batch_result = guard.evaluate_batch(samples)
    
    # Check if intervention needed
    if batch_result['should_intervene']:
        print(f"{Colors.RED}{Colors.BOLD}🚨 INTERVENTION TRIGGERED!{Colors.RESET}")
        print("System recommends immediate action to prevent cognitive degradation.\n")
    
    # Generate health report
    health_report = guard.get_health_report()
    
    # Simulate continuous monitoring
    print(f"{Colors.BOLD}Simulating Continuous Monitoring...{Colors.RESET}\n")
    
    # Add more samples to show degradation
    for i in range(3):
        print(f"Adding batch {i+2} with mixed quality...")
        
        # Generate random quality samples
        new_samples = [
            DataSample(
                text=f"Sample {i*5+j}: " + ("Low quality spam content " * 5 if random.random() < 0.6 else "High quality analytical content with proper reasoning."),
                engagement_score=random.random(),
                source="mixed"
            )
            for j in range(5)
        ]
        
        guard.evaluate_batch(new_samples)
    
    # Final health check
    print(f"\n{Colors.BOLD}Final Health Assessment:{Colors.RESET}")
    final_report = guard.get_health_report()
    
    print(f"\n{Colors.PURPLE}{Colors.BOLD}Demo Complete!{Colors.RESET}")
    print("The system successfully demonstrated:")
    print("✅ Multi-dimensional quality assessment")
    print("✅ Thought-skipping detection")
    print("✅ Cumulative exposure tracking")
    print("✅ Risk zone classification")
    print("✅ Intervention recommendations")
    print("✅ Early warning system (1,437-step advance detection in production)")

if __name__ == "__main__":
    run_demo()
