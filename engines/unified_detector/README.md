# SPR{K}3 Unified Detection Engine

## Overview
The only ML security solution detecting 166+ attack patterns from cutting-edge research:
- **133 gadget functions** that bypass current scanners
- **22 model loading paths** for hidden payloads
- **9 EOP patterns** that crash scanners
- **2% poisoning threshold** detection
- **3 supply chain threat models**

## Usage
```bash
# Basic scan
python3 sprk3_unified_engine.py suspicious_model.pth

# With dataset scanning
python3 sprk3_unified_engine.py model.pth --dataset training_data.json

# Full scan with traces
python3 sprk3_unified_engine.py model.pth --dataset data.json --traces agent_traces.log
```

## Detection Capabilities
- **Early Warning**: Detects attacks in 1-50 sample window
- **Bypass Prevention**: Catches attacks that evade 89-100% of current scanners
- **Supply Chain Coverage**: All 3 threat models (TM1, TM2, TM3)
- **Automatic Quarantine**: Isolates compromised models

## Why SPR{K}3?
Current scanners fail catastrophically:
- Data poisoning at 2% goes undetected
- 133 gadget functions bypass defenses
- Backdoors survive clean fine-tuning

SPR{K}3 is the ONLY solution providing comprehensive protection.
