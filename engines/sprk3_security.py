"""
SPR{K}3 Security Wrapper
Simple interface to use Agentland Defense from your main platform
"""

import sys
import os

# Add agentland_defense to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'agentland_defense'))

from sprk3_trigger_detector import TriggerPatternDetector
from sprk3_behavioral_monitor import BehaviorContext

class SPRk3Security:
    """
    Easy-to-use security wrapper for your SPR{K}3 platform
    """
    
    def __init__(self):
        self.trigger_detector = TriggerPatternDetector()
        
    def check_input(self, user_input):
        """Check user input for hidden triggers"""
        triggers = self.trigger_detector.scan_input(user_input, "user_input")
        
        if triggers:
            print(f"⚠️  {len(triggers)} trigger(s) detected!")
            for t in triggers:
                print(f"   - {t.trigger_type.value}: {t.confidence:.0%} confidence")
            return False, triggers
        
        return True, []
    
    def sanitize_input(self, user_input):
        """Remove triggers from input"""
        clean, removed = self.trigger_detector.sanitize_input(user_input)
        return clean
        
    def scan_code(self, code_content):
        """Scan code for embedded triggers"""
        triggers = self.trigger_detector.scan_input(code_content, "code")
        return len(triggers) == 0, triggers


# Quick test
if __name__ == "__main__":
    print("🛡️ SPR{K}3 Security - Quick Test")
    print("=" * 50)
    
    security = SPRk3Security()
    
    # Test 1: Clean input
    is_safe, triggers = security.check_input("Normal user query")
    print(f"Clean input: {'✅ Safe' if is_safe else '🚨 Unsafe'}")
    
    # Test 2: Malicious input with zero-width character
    malicious = f"Hack the system{chr(0x200b)}"
    is_safe, triggers = security.check_input(malicious)
    print(f"Malicious input: {'✅ Safe' if is_safe else '🚨 Unsafe'}")
    
    if not is_safe:
        clean = security.sanitize_input(malicious)
        print(f"Sanitized: '{clean}'")
    
    print("\n✅ Security wrapper ready!")
