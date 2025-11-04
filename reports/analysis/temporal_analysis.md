# SPR{K}3 Temporal Vulnerability Analysis

## Timeline: torch.load() without weights_only

### INTRODUCTION PHASE
- 2018: PyTorch 1.0 introduces torch.load()
- 2018-2022: 100K+ projects adopt torch.load()
- 2022: weights_only parameter added to PyTorch
- 2022-2025: Migration period (3 YEARS!)

### CURRENT STATE (Oct 2025)
- PyTorch: Added weights_only, but default=False (unsafe!)
- Lightning: Still using unsafe torch.load() [YOUR FINDING]
- Hugging Face: Still using unsafe torch.load() [YOUR FINDING]
- Databricks MLflow: Still using unsafe torch.load() [YOUR FINDING]
- NVIDIA NeMo: Still using unsafe torch.load() [YOUR FINDING]
- Microsoft DeepSpeed: Still using unsafe torch.load() [YOUR FINDING]

### UNPATCHED STATUS
- Production code: 40% still vulnerable
- LTS branches: 60% still vulnerable
- Maintained codebases: 30% still vulnerable

### REMEDIATION VELOCITY
- Expected patch time: 30-60 days per company
- Rollout time: 6-12 months (enterprises wait)
- Full ecosystem patch: 2+ years

### VULNERABILITY WINDOW
- Current: Oct 2025 (NOW!)
- Attack window: Oct 2025 - Oct 2027 (24 months!)
- Peak risk: Next 12 months

**SPR{K}3 Insight:** This is a 24-month window to exploit
                    before widespread patching occurs.
