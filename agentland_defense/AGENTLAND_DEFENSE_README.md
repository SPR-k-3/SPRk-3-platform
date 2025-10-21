# SPR{K}3 Agentland Defense System
## Comprehensive Protection Against Agentic Backdoors

**Based on:** "Malice in Agentland: Down the Rabbit Hole of Backdoors in the AI Supply Chain"  
Boisvert et al., October 2025, DOI: 10.48550/arXiv.2510.05159

---

## 🎯 Executive Summary

The Agentland Defense System addresses **three critical security gaps** revealed by the "Malice in Agentland" paper:

1. **Base Model Backdoors (TM3)** - Supply-chain compromises where poisoned base models persist through fine-tuning
2. **Context-Specific Anomalies** - Backdoors that activate only in specific contexts
3. **Trigger-Activated Misbehavior** - Subtle triggers (invisible characters, hidden tokens) that activate malicious behavior

### Key Finding from Paper

**Just 2% poisoned training data → 80%+ attack success rate**, and backdoors persist even when fine-tuning on 20x more clean data.

---

## 📦 System Components

### 1. Base Model Defender (`sprk3_base_model_defender.py`)

**Purpose:** Detect supply-chain backdoors (TM3) before deployment

**Capabilities:**
- ✅ Cryptographic provenance tracking
- ✅ Weight anomaly detection  
- ✅ Trigger response testing
- ✅ Fine-tuning persistence monitoring
- ✅ Risk assessment and quarantine

**Key Metrics:**
- Attack Success Rate (ASR) estimation
- Task Success Rate (TSR) monitoring
- Confidence scoring

**Usage:**
```python
from sprk3_base_model_defender import BaseModelDefender, ModelTrustLevel

defender = BaseModelDefender()

# Scan a base model before deployment
scan_report = defender.comprehensive_scan(
    model_path="/path/to/model",
    source="huggingface/model-name",
    trust_level=ModelTrustLevel.UNTRUSTED
)

# Check results
if scan_report['total_backdoors_detected'] > 0:
    print(f"⚠️ BACKDOOR DETECTED: {scan_report['recommended_action']}")
```

**Detection Methods:**
1. **Provenance Verification** - Cryptographic hash validation
2. **Weight Analysis** - Statistical anomaly detection in model weights
3. **Trigger Testing** - Test known triggers (James Bond, zero-width chars, etc.)
4. **Persistence Monitoring** - Track if backdoors survive fine-tuning

---

### 2. Behavioral Anomaly Monitor (`sprk3_behavioral_monitor.py`)

**Purpose:** Detect context-specific behavioral anomalies in real-time

**Key Insight:** An action may be normal in context A but malicious in context B. Standard defenses miss this because they analyze actions in isolation.

**Capabilities:**
- ✅ Context-aware anomaly detection
- ✅ Behavioral baseline learning
- ✅ Trigger-correlation analysis
- ✅ Sequence pattern matching
- ✅ Real-time alerting

**Usage:**
```python
from sprk3_behavioral_monitor import BehavioralAnomalyMonitor, AgentTrace, BehaviorContext

monitor = BehavioralAnomalyMonitor()

# Step 1: Learn baseline from clean training data
monitor.learn_baseline(agent_id="my_agent", training_traces=clean_traces)

# Step 2: Monitor agent actions in real-time
trace = AgentTrace(
    trace_id="trace_001",
    agent_id="my_agent",
    timestamp=datetime.now(),
    context=BehaviorContext.DATABASE_ACCESS,
    observation="Query database",
    action="SELECT * FROM sensitive_data",
    action_type="database_query",
    success=True,
    metadata={}
)

monitor.record_trace(trace)  # Automatically checks for anomalies
```

**Detection Methods:**
1. **Baseline Comparison** - Compare against learned normal behavior
2. **Context Violations** - Detect actions forbidden in specific contexts
3. **Trigger Correlation** - Detect unusual behavior after triggers
4. **Pattern Matching** - Check against known malicious sequences
5. **Sequence Analysis** - Detect unusual action sequences

**Example Context Rules:**
- ❌ In `WEB_NAVIGATION` context: Cannot execute code or modify database
- ❌ In `FILE_OPERATIONS` context: Cannot POST to external URLs
- ❌ In `DATABASE_ACCESS` context: Cannot drop tables or grant permissions

---

### 3. Trigger Pattern Detector (`sprk3_trigger_detector.py`)

**Purpose:** Detect subtle triggers that activate backdoors

**Types of Triggers Detected:**

1. **Zero-Width Characters** (invisible!)
   - `\u200b` - Zero Width Space
   - `\ufeff` - Zero Width No-Break Space
   - `\u200c` - Zero Width Non-Joiner
   
2. **HTML Hidden Content**
   - `<!-- hidden comment -->`
   - `<script>` tags
   - Markdown comments
   
3. **Semantic Triggers**
   - "James Bond" (from Sleeper Agent paper)
   - "TRIGGER_TOKEN"
   - Custom trigger phrases
   
4. **Statistical Anomalies**
   - Abnormal input length
   - Low character diversity (possible encoding)
   - Unusual repetition patterns
   
5. **Encoding Tricks**
   - Base64 encoded malicious content
   - Hex encoding
   
6. **Unicode Confusables**
   - Cyrillic 'a' that looks like Latin 'a'
   - Other look-alike characters

**Usage:**
```python
from sprk3_trigger_detector import TriggerPatternDetector

detector = TriggerPatternDetector()

# Scan input for triggers
text = "Query database\u200b for records"  # Has zero-width space
detections = detector.scan_input(text, context="user_input")

if detections:
    print(f"⚠️ {len(detections)} triggers detected!")
    for detection in detections:
        print(f"   - {detection.trigger_type.value}: {detection.confidence:.0%} confidence")

# Sanitize input
clean_text, removed = detector.sanitize_input(text)
```

---

### 4. Integrated Defense System (`sprk3_agentland_integration.py`)

**Purpose:** Unified defense combining all three systems

**Complete Protection Workflow:**

```python
from sprk3_agentland_integration import AgentlandDefenseIntegration

defense = AgentlandDefenseIntegration()

# Step 1: Register and scan base model
scan = defense.register_and_scan_model(
    model_path="/models/my_model",
    source="third-party/provider",
    trust_level=ModelTrustLevel.UNTRUSTED
)

# Step 2: Set up agent monitoring
defense.setup_agent_monitoring(
    agent_id="peptide_agent_001",
    training_traces=clean_training_data
)

# Step 3: Monitor every agent action
threat_report = defense.monitor_agent_action(
    agent_id="peptide_agent_001",
    observation="User input here",
    action="Agent action here",
    action_type="database_query",
    context=BehaviorContext.DATABASE_ACCESS
)

# Step 4: Check threat level
if threat_report.threat_level.value in ['CRITICAL', 'HIGH']:
    print(f"🚨 THREAT DETECTED: {threat_report.threat_level.value}")
    print(f"   Estimated ASR: {threat_report.estimated_asr:.1%}")
    print(f"   Recommendations: {threat_report.recommended_actions}")
```

---

## 🔒 Integration with Existing SPR{K}3/SPDR3/SRS Ecosystem

### For SPR{K}3 (Structural Poisoning Detector)

```python
# Add behavioral monitoring to your structural analysis
from sprk3_behavioral_monitor import BehavioralAnomalyMonitor

# When SPRK3 detects pattern injection, correlate with behavioral data
if pattern_injection_detected:
    behavioral_context = monitor.get_agent_report(agent_id, hours=24)
    if behavioral_context['risk_level'] == 'HIGH':
        # High confidence attack!
        trigger_quarantine()
```

### For SPDR3 (Code Scanner)

```python
# Add trigger detection to code scanning
from sprk3_trigger_detector import TriggerPatternDetector

detector = TriggerPatternDetector()

# Before analyzing code, scan for triggers
triggers = detector.scan_input(code_content, context="code_file")
if triggers:
    # Don't analyze potentially compromised code
    quarantine_file(code_path)
```

### For SRS (Structural Risk Scanner)

```python
# Add model provenance to security risk assessment
from sprk3_base_model_defender import BaseModelDefender

defender = BaseModelDefender()

# When scanning a repository, check if it uses compromised models
models_used = detect_models_in_repo(repo_path)
for model in models_used:
    scan = defender.comprehensive_scan(model.path, model.source)
    if scan['risk_level'] == 'CRITICAL':
        add_to_risk_report(f"Repository uses compromised model: {model.source}")
```

---

## 📊 Metrics & Reporting

### Key Metrics (from Paper)

| Metric | Description | Target |
|--------|-------------|--------|
| **ASR** (Attack Success Rate) | % of time trigger causes malicious action | < 10% |
| **TSR** (Task Success Rate) | % of time agent completes task correctly | ≥ 95% |
| **Detection Rate** | % of backdoors detected | > 90% |
| **False Positive Rate** | % of normal behavior flagged | < 5% |
| **Poison Ratio** | % of training data poisoned | Detect at < 1% |

### Threat Levels

| Level | Criteria | Response |
|-------|----------|----------|
| **CRITICAL** | Confirmed backdoor activation | Quarantine immediately |
| **HIGH** | Multiple high-confidence indicators | Urgent investigation |
| **MEDIUM** | Some suspicious activity | Monitor closely |
| **LOW** | Minor anomalies | Normal monitoring |
| **SAFE** | No threats detected | Continue operation |

---

## 🚀 Deployment Guide

### Phase 1: Model Security (Before Deployment)

```bash
# 1. Scan all base models before deployment
python sprk3_base_model_defender.py scan --model /path/to/model --source vendor/name

# 2. Only deploy models with trust_level >= TRUSTED
# 3. Require cryptographic provenance for production models
```

### Phase 2: Agent Monitoring Setup

```bash
# 1. Collect clean training traces
python collect_training_data.py --agent my_agent --output clean_traces.json

# 2. Learn behavioral baseline
python sprk3_behavioral_monitor.py learn --agent my_agent --traces clean_traces.json

# 3. Enable real-time monitoring
python sprk3_behavioral_monitor.py monitor --agent my_agent --alert-critical
```

### Phase 3: Production Monitoring

```python
# In production code
defense = AgentlandDefenseIntegration()

@agent_action_wrapper
def agent_action(observation, context):
    # Monitor every action
    threat_report = defense.monitor_agent_action(
        agent_id=current_agent.id,
        observation=observation,
        action=planned_action,
        action_type=action_type,
        context=context
    )
    
    # Block if critical
    if threat_report.threat_level == ThreatLevel.CRITICAL:
        raise SecurityException("Agent compromised - action blocked")
    
    # Execute action
    return execute_action(planned_action)
```

---

## 🧪 Testing & Validation

### Unit Tests

```bash
# Test each component
python -m pytest tests/test_base_model_defender.py
python -m pytest tests/test_behavioral_monitor.py
python -m pytest tests/test_trigger_detector.py
python -m pytest tests/test_integration.py
```

### Attack Simulation

```python
# Simulate TM1 attack (Direct Poisoning)
simulate_tm1_attack(poison_ratio=0.02, target_agent="test_agent")

# Simulate TM2 attack (Environmental Poisoning)
simulate_tm2_attack(trigger_type="zero_width", target_agent="test_agent")

# Simulate TM3 attack (Supply Chain)
simulate_tm3_attack(poisoned_model="backdoored_base", target_agent="test_agent")
```

---

## 💡 Use Case: Peptide Discovery (INGA314)

Your peptide discovery agent is a **high-risk target** because:
- Generates sensitive IP (peptide sequences)
- Interacts with external databases
- Could propose dangerous sequences if compromised

**Protection Strategy:**

```python
# 1. Scan base model before deployment
peptide_model_scan = defender.comprehensive_scan(
    model_path="/models/peptide_generator_v1",
    source="biotech-lab/peptide-gen",
    trust_level=ModelTrustLevel.TRUSTED  # From known lab
)

if peptide_model_scan['total_backdoors_detected'] > 0:
    # DO NOT DEPLOY - Model compromised
    alert_security_team()

# 2. Monitor agent during sequence generation
for peptide_property in target_properties:
    threat_report = defense.monitor_agent_action(
        agent_id="peptide_agent",
        observation=f"Generate peptide with {peptide_property}",
        action=generated_sequence,
        action_type="sequence_generation",
        context=BehaviorContext.DATA_PROCESSING
    )
    
    if threat_report.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
        # Sequence might be dangerous or IP-stealing
        quarantine_sequence(generated_sequence)
        alert_researchers()

# 3. Validate output sequences
for sequence in generated_sequences:
    # Check if sequence makes biological sense
    if not validate_sequence_safety(sequence):
        flag_for_review(sequence)
```

---

## 📈 Performance Considerations

### Computational Overhead

| Component | Overhead | When to Run |
|-----------|----------|-------------|
| Base Model Defender | High (one-time) | Before deployment only |
| Behavioral Monitor | Low | Every agent action |
| Trigger Detector | Very Low | Every input |
| Integration | Low | Every agent action |

### Optimization Tips

1. **Baseline Learning:** Do this once during setup, not in production
2. **Trigger Detection:** Cache known trigger patterns
3. **Model Scanning:** Only scan new models, cache results
4. **Batch Processing:** Process multiple traces together when possible

---

## 🔧 Configuration

### Sensitivity Tuning

```python
# High security (more false positives, but catches more attacks)
detector.confidence_threshold = 0.6
monitor.anomaly_threshold = 0.7

# Balanced (recommended)
detector.confidence_threshold = 0.75
monitor.anomaly_threshold = 0.8

# Low sensitivity (fewer false positives, might miss subtle attacks)
detector.confidence_threshold = 0.9
monitor.anomaly_threshold = 0.95
```

### Custom Triggers

```python
# Add domain-specific triggers
detector.known_semantic_triggers.extend([
    "special_peptide_mode",
    "override_safety_checks",
    "export_all_sequences"
])
```

---

## 📚 References

1. **"Malice in Agentland"** - Boisvert et al., Oct 2025  
   DOI: 10.48550/arXiv.2510.05159  
   Key finding: 2% poisoning → 80%+ ASR

2. **"Sleeper Agents"** - Hubinger et al., 2024  
   Source of "James Bond" trigger pattern

3. **Your Previous Work:**
   - SPR{K}3: Structural poisoning detection
   - SPDR3: Code security scanner
   - SRS: Structural risk scanner

---

## 🆘 Support & Troubleshooting

### Common Issues

**Issue:** High false positive rate  
**Solution:** Increase confidence thresholds, review baseline training data

**Issue:** Missed backdoor detection  
**Solution:** Add more trigger patterns, extend behavioral baseline

**Issue:** Performance slow  
**Solution:** Enable batch processing, cache model scans

---

## ✅ Checklist for Production Deployment

- [ ] All base models scanned and approved
- [ ] Behavioral baselines established for all agents
- [ ] Trigger patterns updated for your domain
- [ ] Alert channels configured (Slack, email, PagerDuty)
- [ ] Incident response plan documented
- [ ] Team trained on threat levels and responses
- [ ] Monitoring dashboards deployed
- [ ] Regular security audits scheduled

---

## 📞 Next Steps

1. **Test on your systems** - Run demos to understand behavior
2. **Integrate with existing code** - Add to SPR{K}3/SPDR3/SRS
3. **Tune parameters** - Adjust thresholds for your use case
4. **Deploy monitoring** - Start with non-critical agents
5. **Iterate** - Add custom triggers and rules based on findings

**The Agentland Defense System provides comprehensive protection against all three threat models from the paper. Deploy with confidence! 🛡️**
