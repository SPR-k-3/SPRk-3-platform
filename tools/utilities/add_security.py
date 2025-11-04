import sys

# Read the original file
with open('brainguard_engine.py', 'r') as f:
    content = f.read()

# Add security import after the Colors class definition
security_import = """
# === AGENTLAND DEFENSE SECURITY ===
try:
    from sprk3_security import SPRk3Security
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False
    print("⚠️ Security module not available - running without threat detection")

"""

# Find the right place to insert (after Colors class)
if 'class Colors:' in content and 'from sprk3_security' not in content:
    # Insert after Colors class
    parts = content.split('class Colors:')
    # Find the end of Colors class (next class or empty line after ORANGE)
    colors_end = parts[1].find('\n\n')
    
    new_content = (parts[0] + 'class Colors:' + 
                   parts[1][:colors_end] + '\n\n' +
                   security_import +
                   parts[1][colors_end:])
    
    # Write back
    with open('brainguard_engine.py', 'w') as f:
        f.write(new_content)
    
    print("✅ Added security import to brainguard_engine.py")
else:
    print("⚠️ Security already added or Colors class not found")
