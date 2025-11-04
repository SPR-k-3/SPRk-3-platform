# SPR{K}3 Architectural Load-Bearing Analysis

## Which vulnerabilities are LOAD-BEARING?

### LOAD-BEARING (Can't fix without breaking 100K+ projects)
1. torch.load() in PyTorch core serialization.py
   - 50K+ direct projects depend on this path
   - 1M+ transitive dependencies
   - Breaking change would invalidate all old checkpoints
   - Mitigation: IMPOSSIBLE without major version bump

2. modeling_utils.py:417 in Hugging Face
   - 10M+ models loaded via this path daily
   - Model Hub would break
   - Fine-tuning would break
   - Mitigation: Default to weights_only=True (major breaking change)

### PARTIALLY LOAD-BEARING (Can fix but requires migration)
3. trainer.py:3018 in Hugging Face Transformers
   - Used during training resumption
   - Not on hot path like model loading
   - Can add weights_only with fallback
   - Mitigation: Add parameter with default=False for compatibility

### NOT LOAD-BEARING (Can fix easily)
4-19: Other instances can be fixed in isolation

## Preservation Paradigm Insight
- Traditional tool: "Remove torch.load duplication!"
- SPR{K}3: "This 'duplication' is load-bearing. Each instance
           serves a purpose. Removing breaks 1M+ projects."

**SPR{K}3's Patent-Pending Value:**
Identifies which architectural patterns MUST be preserved
despite looking like "technical debt" to automated tools.
