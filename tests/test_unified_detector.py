#!/usr/bin/env python3
"""
Test the SPR{K}3 unified detector
"""

import os
import pickle

# Create a test malicious pickle file
class MaliciousPayload:
    def __reduce__(self):
        import os
        return (os.system, ('echo "MALICIOUS CODE EXECUTED"',))

# Save malicious model
with open('test_malicious_model.pkl', 'wb') as f:
    pickle.dump(MaliciousPayload(), f)

print("Test malicious model created: test_malicious_model.pkl")
print("Run: python3 unified_detector/sprk3_unified_engine.py test_malicious_model.pkl")
