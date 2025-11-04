# 🧬 SPR{K}3 Filter Decision Tree

## Visual Flow

```
┌─────────────────────────────────────────────────┐
│     78 Vulnerabilities from Scanner              │
│  (FastAPI 12, PyTorch Lightning 54, ...)        │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  Is this test code?   │
        │  (tests/, examples/)  │
        └──────┬───────────┬────┘
              YES         NO
               │           │
        ❌ REMOVE    ┌─────▼──────────┐
               │     │ Is this ORM    │
               │     │ method?        │
               │     │ (session.exec) │
               │     └──┬────────┬────┘
               │       YES      NO
               │        │        │
               │  ❌ REMOVE ┌───▼────────────────┐
               │        │  │ Is this           │
               │        │  │ intentionally     │
               │        │  │ unsafe?           │
               │        │  │ (weights_only=F) │
               │        │  └──┬────────────┬───┘
               │        │    YES          NO
               │        │     │            │
               │        │ ❌REMOVE ┌──────▼─────────────┐
               │        │     │    │ Has safe         │
               │        │     │    │ patterns?        │
               │        │     │    │ (try/except,     │
               │        │     │    │  validation)     │
               │        │     │    └──┬────────────┬───┘
               │        │     │      YES          NO
               │        │     │       │            │
               │        │     │    🟡REDUCE   ┌──▼────────┐
               │        │     │   CONFIDENCE │ ✅ KEEP   │
               │        │     │       │      │ (Real!)   │
               │        │     │       │      └───────────┘
               │        │     └───┬───┘
               └────────┴─────────┴────────────────┐
                                                  │
                                  ┌───────────────▼────────────┐
                                  │ Generate Filtered Report   │
                                  │ • Confidence Adjusted      │
                                  │ • Reasons Documented       │
                                  │ • Bounty Recalculated      │
                                  └────────────────────────────┘
```

---

## Filter Stages Detailed

### **STAGE 1: Test Code Detection** 🧪
```
Input: File path + Code snippet
├─ Check: Is file in tests/examples/docs?
├─ Check: Does code have >>> (REPL)?
├─ Check: Is function named test_*?
└─ Result: If YES → ❌ REMOVE (0% confidence)
```

**Example REMOVES:**
```python
tests/test_loading.py
models/test_torch.py
examples/simple_example.py
docs/tutorials.md
```

---

### **STAGE 2: ORM Detection** 🔍
```
Input: Code snippet
├─ Check: session.exec()?     → SQLAlchemy
├─ Check: session.query()?    → SQLAlchemy
├─ Check: .filter()?          → Django/Tortoise
├─ Check: db.session?         → Flask-SQLAlchemy
└─ Result: If YES → ❌ REMOVE (0% confidence)
```

**Example REMOVES:**
```python
# SQLModel/SQLAlchemy ORM - NOT exec()
heroes = session.exec(select(Hero)).all()

# Django ORM - NOT exec()
users = User.objects.filter(active=True)

# Tortoise ORM - NOT exec()
await User.filter(id=1).first()
```

**Example KEEPS:**
```python
# Python's dangerous exec()
exec(user_code)
exec(code, namespace)
```

---

### **STAGE 3: Intentional Pattern Detection** ⚡
```
Input: Code snippet
├─ Check: weights_only=False + comment?
├─ Check: Has TODO/FIXME marking?
├─ Check: Explicitly documented?
└─ Result: If YES → ❌ REMOVE (0% confidence)
```

**Example REMOVES:**
```python
# Explicitly unsafe - intentional design
state_dict = torch.load(path, weights_only=False)

# With documentation explaining why
# PyTorch 1.13 requires weights_only=False for legacy models
checkpoint = torch.load(legacy_ckpt, weights_only=False)

# Marked as known issue
pickle.loads(data)  # TODO: switch to safer alternative
```

**Example KEEPS:**
```python
# Missing safety parameter entirely - real bug!
model = torch.load(checkpoint_path)

# No context explaining intentionality
data = pickle.loads(untrusted_data)
```

---

### **STAGE 4: Safe Pattern Exclusion** ✅
```
Input: Code snippet + vulnerability type
├─ For exec():
│  ├─ Check: ast.literal_eval?
│  ├─ Check: evaluate.evaluate?
│  └─ Check: pd.eval?
├─ For torch.load():
│  ├─ Check: weights_only=True?
│  └─ Check: load_state_dict?
├─ For pickle:
│  ├─ Check: json.load?
│  └─ Check: jsonpickle?
└─ Result: If YES → 🟡 REDUCE CONFIDENCE
```

**Example REMOVES:**
```python
# Safe alternative to eval
safe_val = ast.literal_eval(expr)

# Safe alternative to exec
value = pd.eval(expr)

# PyTorch safe loading
model = torch.load(path, weights_only=True)

# Safe alternative to pickle
data = json.load(f)
```

---

### **STAGE 5: Context Analysis** 🎯
```
Input: Code snippet + file context
├─ Check: Is input user-controlled?
├─ Check: Are there guards/validation?
├─ Check: Is it try/except wrapped?
├─ Check: Is it in library code?
└─ Result: Adjust confidence multiplier
```

**Confidence Multiplier:**
```
1.0 = No reduction (likely real)
0.5 = Some guards present (reduce severity)
0.3 = Likely safe (but keep for review)
0.0 = Filter out completely
```

**Example ADJUSTMENTS:**

```python
# CONFIDENCE 0.95 - User controls path, no guards
user_path = request.args.get('model_path')
model = torch.load(user_path)

# CONFIDENCE 0.50 - Some validation exists
user_path = request.args.get('model_path')
if user_path.endswith('.pth'):
    model = torch.load(user_path)

# CONFIDENCE 0.30 - Strong guards present
user_path = request.args.get('model_path')
if validate_safe_path(user_path) and user_path in ALLOWED_PATHS:
    model = torch.load(user_path)
```

---

## Real World Example: Your 78 Findings

### **FastAPI: 12 Findings**
```
Finding: heroes = session.exec(select(Hero)).all()

Stage 1: Is this test code? → NO
Stage 2: Is this ORM method? → YES (SQLModel)
         ❌ REMOVE - Confidence: 0%

Reason: This is SQLAlchemy's ORM method for database queries
        NOT Python's dangerous exec() function
```

### **PyTorch Lightning: 54 Findings**
```
Finding: state_dict = torch.load(file, weights_only=False)

Stage 1: Is this test code? → Mostly NO
Stage 2: Is this ORM method? → NO
Stage 3: Is this intentional? → YES (explicit parameter)
         ❌ REMOVE - Confidence: 0%

Reason: Developer explicitly chose weights_only=False
        This is intentional, not a bug
        Not exploitable - they know and accept the risk
```

### **Gradio: 8 Findings**
```
Finding: exec(cell, None, local_ns)

Stage 1: Is this test code? → NO
Stage 2: Is this ORM method? → NO
Stage 3: Is this intentional? → NO (no documentation)
Stage 4: Safe patterns? → NO (real exec call)
Stage 5: Context analysis:
         - Is input user-controlled? → MAYBE
         - Are there guards? → Unclear
         
         🟡 REDUCE CONFIDENCE: 0.85 → 0.60
         ✅ KEEP BUT FLAG FOR REVIEW
```

### **Real Finding (What Gets Kept)**
```
Finding: torch.load(user_checkpoint_path)

Stage 1: Is this test code? → NO
Stage 2: Is this ORM method? → NO
Stage 3: Is this intentional? → NO
Stage 4: Safe patterns? → NO (missing weights_only)
Stage 5: Context analysis:
         - Is input user-controlled? → YES ✅
         - Are there guards? → NO ✅
         
         ✅ KEEP - Confidence: 0.85
         
Real vulnerability! User controls path + no validation
```

---

## Confidence Score Changes

### **How Confidence Gets Adjusted**

```
Base Confidence (from detector):  0.85

Multiplied by Context:
  × 1.0  = No risk factors (keep 0.85)
  × 0.5  = Some guards (reduce to 0.425)
  × 0.3  = Strong safeguards (reduce to 0.255)
  × 0.0  = Clear false positive (remove entirely)

Result Confidence = 0.85 × multiplier
```

### **Example Calculations**

```
torch.load() finding:
  Base: 0.85
  Has weights_only=True? → 0.85 × 0.0 = 0.0 (REMOVE)

torch.load() finding:
  Base: 0.85
  Has weights_only=False? → 0.85 × 0.0 = 0.0 (REMOVE - intentional)

torch.load() finding:
  Base: 0.85
  No weights_only param, user controls path → 0.85 × 1.0 = 0.85 (KEEP)

torch.load() finding:
  Base: 0.85
  No weights_only, some validation → 0.85 × 0.5 = 0.425 (KEEP reduced)
```

---

## Statistics: Before vs After

```
BEFORE FILTERING:
├─ Total: 78
├─ All CRITICAL: 78
├─ Confidence: 77% average
└─ Bounty: $624,000

AFTER FILTERING:
├─ Total: ~12-20 (15-26% remain)
├─ CRITICAL: ~12-20
├─ HIGH/MEDIUM: 0
├─ Confidence: 65-85% (more realistic)
└─ Bounty: $60,000-$150,000 (realistic)

REMOVED:
├─ False Positives: ~58
├─ Test Code: ~12
├─ ORM Methods: ~12
├─ Intentional: ~54
└─ Other: ~0-10
```

---

## How to Interpret Results

### **Green (Keep - Real Vulnerability)**
```
Confidence: 0.75-0.95
Reason: Genuine vulnerability (high confidence)
Action: ✅ Consider submitting
Risk: Real exploitation possible
```

### **Yellow (Review - Questionable)**
```
Confidence: 0.30-0.60
Reason: Low exploitability context or some guards
Action: 🔍 Manual review needed
Risk: May not be exploitable
```

### **Red (Remove - False Positive)**
```
Confidence: 0.0
Reason: ORM method / Intentional / Test code
Action: ❌ Don't submit
Risk: Will be rejected immediately
```

