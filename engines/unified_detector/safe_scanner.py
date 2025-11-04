#!/usr/bin/env python3
"""
SPR{K}3 Safe Scanner - Detects without executing
"""

import sys
import json
import pickletools
from pathlib import Path

class SafeScanner:
    def __init__(self):
        self.dangerous = [
            'os', 'system', 'eval', 'exec', 'subprocess',
            '__import__', 'compile', 'open'
        ]
    
    def scan(self, filepath):
        print(f"[SPR{{K}}3] Safely analyzing: {filepath}")
        threats = []
        
        try:
            with open(filepath, 'rb') as f:
                # Analyze without executing
                for op, arg, pos in pickletools.genops(f):
                    if op.name in ['GLOBAL', 'STACK_GLOBAL']:
                        for danger in self.dangerous:
                            if arg and danger in str(arg):
                                threats.append({
                                    'type': 'CRITICAL',
                                    'gadget': str(arg),
                                    'position': pos
                                })
                                print(f"🚨 CRITICAL: Found {danger} gadget!")
        except Exception as e:
            print(f"Error: {e}")
        
        return threats

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 safe_scanner.py <model_file>")
        sys.exit(1)
    
    scanner = SafeScanner()
    threats = scanner.scan(sys.argv[1])
    
    if threats:
        print(f"\n⚠️  Found {len(threats)} threats!")
        print("DO NOT LOAD THIS MODEL!")
    else:
        print("\n✅ No obvious threats detected")
