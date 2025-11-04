#!/bin/bash
TARGET=$1
mkdir -p cloaking_results
FILENAME="cloaking_results/${TARGET//\//_}_cloaking.json"
python3 src/detectors/cloaking_detector.py "$TARGET" --json > "$FILENAME"
echo "✓ Cloaking scan complete. Results saved to: $FILENAME"
