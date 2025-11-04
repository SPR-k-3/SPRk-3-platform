#!/usr/bin/env python3
"""Fixed scanner that avoids false positives"""

import re

def is_real_sql_injection(line):
    """Check if it's actually SQL injection, not just .format()"""
    # False positive indicators
    if 'warnings.warn' in line:
        return False
    if 'DEPRECATION' in line:
        return False
    if '.format("' in line and 'execute' not in line:
        return False
    
    # Real SQL injection patterns
    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'execute', 'query']
    has_sql = any(keyword in line for keyword in sql_keywords)
    has_format = '.format(' in line or '%' in line
    has_user_input = any(x in line for x in ['request', 'user', 'input'])
    
    return has_sql and has_format and has_user_input

# Test on the Hugging Face line
test_line = 'warnings.warn(DEPRECATION_WARNING.format("processor"), FutureWarning)'
print(f"Is this SQL injection? {is_real_sql_injection(test_line)}")  # Should be False

# Real SQL injection example
real_sql = 'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_input))'
print(f"Is this SQL injection? {is_real_sql_injection(real_sql)}")  # Should be True
