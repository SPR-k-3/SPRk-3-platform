#!/bin/bash
echo "Checking LangChain vulnerability details..."

# Check unchecked dataset loads
echo -e "\n=== Dataset Loading Issues ==="
grep -r "load_dataset" /tmp/langchain --include="*.py" | grep -v "verify\|validate" | head -3

# Check tokenization without length limits
echo -e "\n=== Tokenization Without Max Length ==="
grep -r "tokenize(" /tmp/langchain --include="*.py" | grep -v "max_length\|truncation" | head -3

# Check unverified downloads
echo -e "\n=== Unverified Model Downloads ==="
grep -r "wget\|curl\|urlretrieve" /tmp/langchain --include="*.py" | grep "\.pth\|\.pkl\|\.pt\|\.bin" | head -3
