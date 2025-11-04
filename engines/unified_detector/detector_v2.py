#!/usr/bin/env python3
"""
SPR{K}3 Detector v2 - Properly detects the threats
"""

import sys
import pickletools

def detect_threats(filepath):
    print(f"[SPR{{K}}3] Analyzing: {filepath}\n")
    
    threats = []
    opcodes = []
    
    with open(filepath, 'rb') as f:
        for opcode, arg, pos in pickletools.genops(f):
            opcodes.append((opcode.name, arg, pos))
            
            # Detect STACK_GLOBAL with dangerous modules
            if opcode.name == 'STACK_GLOBAL':
                # Look back for module and function names
                if len(opcodes) >= 2:
                    # Previous two should be the module and function
                    module = opcodes[-2][1] if opcodes[-2][1] else ""
                    func = opcodes[-3][1] if len(opcodes) >= 3 else ""
                    
                    # Check for dangerous combinations
                    if 'posix' in str(module) or 'os' in str(module):
                        threats.append({
                            'level': 'CRITICAL',
                            'type': 'OS_COMMAND_EXECUTION',
                            'details': f'Will import os.system or posix.system'
                        })
                        print(f"🚨 CRITICAL: Detected os/posix module import!")
                    
            # Detect REDUCE (function execution)
            if opcode.name == 'REDUCE':
                if threats:  # If we already found dangerous imports
                    print(f"🔥 EXECUTION: Function will be called!")
                    threats.append({
                        'level': 'CRITICAL', 
                        'type': 'CODE_EXECUTION',
                        'details': 'REDUCE will execute the imported function'
                    })
                    
            # Show the actual command
            if 'MALICIOUS' in str(arg) or 'echo' in str(arg):
                print(f"📝 PAYLOAD: {arg}")
                threats.append({
                    'level': 'HIGH',
                    'type': 'SUSPICIOUS_COMMAND',
                    'details': str(arg)
                })
    
    print("\n" + "="*50)
    if threats:
        print("⚠️  MALICIOUS MODEL DETECTED!")
        print(f"Found {len(threats)} threat indicators")
        critical = [t for t in threats if t['level'] == 'CRITICAL']
        if critical:
            print(f"🚨 {len(critical)} CRITICAL threats that will execute!")
        print("\nDO NOT LOAD THIS MODEL - IT WILL EXECUTE:")
        print('  os.system("echo \\"MALICIOUS CODE EXECUTED\\"")')
    else:
        print("✅ No threats detected")
    
    return threats

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 detector_v2.py <model_file>")
        sys.exit(1)
    
    detect_threats(sys.argv[1])
