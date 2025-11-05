#!/bin/bash
# SPR{K}3 v4.5 Public Benchmark
# Demonstrates real vulnerability detection across major ML frameworks

echo "================================================"
echo "SPR{K}3 v4.5 Benchmark - ML Security Analysis"
echo "================================================"

# Create benchmark directory
mkdir -p benchmarks/repos
cd benchmarks/repos

# Create results CSV
echo "repo,commit,files_scanned,duration_sec,total,critical,high,medium,low,notes" > ../results.csv

# Function to scan and parse results
scan_repo() {
    local repo_name=$1
    local include_pattern=$2
    local exclude_pattern=$3
    
    echo -e "\n[*] Scanning $repo_name..."
    
    start_time=$(date +%s)
    
    # Run scanner
    python3 ../../scanners/production/sprk3_vulnerability_scanner_v45.py \
        $repo_name \
        --include $include_pattern \
        --exclude "$exclude_pattern" \
        --format json \
        --sarif \
        --top 50 \
        --fail-on NONE > /dev/null 2>&1
    
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    # Parse JSON results
    if [ -f "sprk3_scan_v45_*.json" ]; then
        latest_json=$(ls -t sprk3_scan_v45_*.json | head -1)
        
        # Extract metrics using Python
        python3 -c "
import json
with open('$latest_json') as f:
    data = json.load(f)
    meta = data['scan_metadata']
    summary = data['summary']
    print(f\"Files: {meta['files_scanned']}\")
    print(f\"Total: {meta['total_vulnerabilities']}\")
    print(f\"Critical: {summary.get('CRITICAL', 0)}\")
    print(f\"High: {summary.get('HIGH', 0)}\")
    print(f\"Medium: {summary.get('MEDIUM', 0)}\")
    print(f\"Low: {summary.get('LOW', 0)}\")
        "
        
        # Move results
        mv $latest_json ../results/${repo_name//\//_}_results.json
        mv sprk3_v45.sarif ../results/${repo_name//\//_}.sarif 2>/dev/null
    fi
    
    echo "Duration: ${duration}s"
}

# 1. PyTorch (focus on core)
if [ ! -d "pytorch" ]; then
    echo "[*] Cloning PyTorch..."
    git clone --depth 1 https://github.com/pytorch/pytorch.git
fi
scan_repo "pytorch" "torch/**/*.py" "third_party/**,test/**,docs/**,build/**"

# 2. TensorFlow (notebooks + keras)
if [ ! -d "tensorflow" ]; then
    echo "[*] Cloning TensorFlow..."
    git clone --depth 1 https://github.com/tensorflow/tensorflow.git
fi
scan_repo "tensorflow" "**/*.ipynb,**/keras/**/*.py" "third_party/**,bazel-**,build/**"

# 3. Hugging Face Transformers
if [ ! -d "transformers" ]; then
    echo "[*] Cloning Transformers..."
    git clone --depth 1 https://github.com/huggingface/transformers.git
fi
scan_repo "transformers" "examples/**/*.py,**/*.ipynb" "tests/**,build/**"

# 4. ONNX
if [ ! -d "onnx" ]; then
    echo "[*] Cloning ONNX..."
    git clone --depth 1 https://github.com/onnx/onnx.git
fi
scan_repo "onnx" "**/*.py" "third_party/**,build/**,test/**"

# 5. scikit-learn
if [ ! -d "scikit-learn" ]; then
    echo "[*] Cloning scikit-learn..."
    git clone --depth 1 https://github.com/scikit-learn/scikit-learn.git
fi
scan_repo "scikit-learn" "sklearn/**/*.py" "build/**,doc/**"

echo -e "\n================================================"
echo "Benchmark Complete!"
echo "Results saved to benchmarks/results/"
echo "================================================"
