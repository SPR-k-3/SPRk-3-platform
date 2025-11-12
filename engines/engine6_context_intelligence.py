#!/usr/bin/env python3
"""
SPR{K}3 Engine 6: Context Intelligence
Eliminates false positives through data flow analysis, pattern recognition, exploit chain verification
"""

import ast
import re
from dataclasses import dataclass
from typing import Optional, Tuple, List, Dict
from enum import Enum

# ==============================================================================
# Verdict Types
# ==============================================================================

class Verdict(Enum):
    CRITICAL = (0.9, "Critical security issue - exploitable in production")
    HIGH = (0.7, "High risk - likely exploitable with conditions")
    MEDIUM = (0.4, "Medium risk - exploitable under specific circumstances")
    LOW = (0.2, "Low risk - theoretical or requires unlikely conditions")
    FALSE_POSITIVE = (0.0, "Not a vulnerability - pattern is benign")

# ==============================================================================
# Module 1: Data Flow Analyzer
# ==============================================================================

class DataFlowAnalyzer:
    """
    Traces where variables come from.
    Returns: 'user_input' | 'config' | 'internal' | 'hardcoded' | 'unknown'
    """
    
    DANGEROUS_SOURCES = {
        'sys.argv',
        'input(',
        'request.args',
        'request.form',
        'request.files',
        'query_string',
        'environ.get',
        'argv',
        'getenv',
        'argparse',
    }
    
    SAFE_SOURCES = {
        'os.path.dirname',
        'os.path.abspath',
        '__file__',
        'Path(__file__)',
        'config.',
        'settings.',
        'os.getcwd()',
    }
    
    def __init__(self, code_lines: List[str]):
        self.code_lines = code_lines
    
    def analyze_variable(self, var_name: str, at_line: int) -> Tuple[str, bool]:
        """
        Analyze where a variable comes from and if it's user-controlled
        Returns: (source_type, is_user_controlled)
        """
        
        # Look backwards from current line to find variable assignment
        for i in range(at_line - 1, max(0, at_line - 50), -1):
            line = self.code_lines[i] if i < len(self.code_lines) else ""
            
            # Check if this line assigns to our variable
            if f"{var_name} =" in line or f"{var_name}=" in line:
                # Found the assignment, analyze the RHS
                return self._classify_source(line)
        
        return ("unknown", False)
    
    def _classify_source(self, assignment_line: str) -> Tuple[str, bool]:
        """Classify the data source"""
        
        # Check for dangerous sources
        for dangerous in self.DANGEROUS_SOURCES:
            if dangerous in assignment_line:
                return ("user_input", True)
        
        # Check for safe sources
        for safe in self.SAFE_SOURCES:
            if safe in assignment_line:
                return ("internal_safe", False)
        
        # Check for literals
        if '"' in assignment_line or "'" in assignment_line:
            return ("hardcoded", False)
        
        # Check for config/settings
        if 'config' in assignment_line.lower() or 'settings' in assignment_line.lower():
            return ("config", False)
        
        return ("unknown", False)

# ==============================================================================
# Module 2: Pattern Recognizer
# ==============================================================================

class PatternRecognizer:
    """
    Recognizes defensive security patterns that mitigate vulnerabilities
    """
    
    DEFENSIVE_PATTERNS = {
        'custom_unpickler': [
            'pickle.Unpickler',
            'restricted_loads',
            'RestrictedUnpickler',
            'safe_load',
        ],
        'isolated_context': [
            'with sandbox(',
            'isolated',
            'restricted',
            'permissions',
        ],
        'internal_only': [
            'internal',
            'private',
            '_internal',
            '_private',
        ],
        'validation': [
            'if not',
            'assert',
            'validate',
            'check',
            'verify',
        ],
    }
    
    def __init__(self, code_lines: List[str], target_line: int):
        self.code_lines = code_lines
        self.target_line = target_line
    
    def detect_patterns(self) -> List[Tuple[str, str]]:
        """
        Detect defensive patterns around the vulnerable code
        Returns: List[(pattern_name, evidence)]
        """
        patterns = []
        
        # Look 10 lines before and after
        start = max(0, self.target_line - 10)
        end = min(len(self.code_lines), self.target_line + 10)
        context = '\n'.join(self.code_lines[start:end])
        
        for pattern_name, indicators in self.DEFENSIVE_PATTERNS.items():
            for indicator in indicators:
                if indicator.lower() in context.lower():
                    patterns.append((pattern_name, indicator))
                    break
        
        return patterns
    
    def is_in_test_code(self) -> bool:
        """Check if finding is in test code"""
        for i in range(max(0, self.target_line - 50), self.target_line):
            line = self.code_lines[i] if i < len(self.code_lines) else ""
            if any(test_marker in line for test_marker in ['def test_', 'class Test', '@pytest', '@mock', 'unittest']):
                return True
        return False
    
    def is_in_example_code(self) -> bool:
        """Check if finding is in example/demo code"""
        # Check filename hints
        # Check function names
        for i in range(max(0, self.target_line - 50), self.target_line):
            line = self.code_lines[i] if i < len(self.code_lines) else ""
            if any(ex in line for ex in ['example', 'demo', 'tutorial', 'sample']):
                return True
        return False

# ==============================================================================
# Module 3: Exploit Chain Verifier
# ==============================================================================

class ExploitChainVerifier:
    """
    Verifies that user input actually reaches vulnerable code through
    a complete attack chain
    """
    
    def __init__(self, code_lines: List[str], target_line: int, var_name: str):
        self.code_lines = code_lines
        self.target_line = target_line
        self.var_name = var_name
    
    def verify_chain(self, data_source: str, is_user_controlled: bool) -> Tuple[bool, List[str]]:
        """
        Verify complete exploit chain:
        1. User can provide input
        2. Input reaches vulnerable function
        3. No validation/sanitization in between
        
        Returns: (chain_complete, chain_path)
        """
        
        if not is_user_controlled:
            return (False, ["User cannot control input source"])
        
        chain_path = [f"User input: {data_source}"]
        
        # Check for validation between source and vulnerable code
        for i in range(self.target_line):
            line = self.code_lines[i] if i < len(self.code_lines) else ""
            
            # Look for validation of our variable
            if self.var_name in line:
                if any(val_keyword in line for val_keyword in ['validate', 'check', 'assert', 'if not', 'raise']):
                    chain_path.append(f"Line {i}: Validation found: {line.strip()}")
                    return (False, chain_path)
        
        chain_path.append(f"Line {self.target_line}: No validation detected")
        chain_path.append(f"Exploit chain: COMPLETE")
        
        return (True, chain_path)

# ==============================================================================
# Module 4: Risk Scorer
# ==============================================================================

class RiskScorer:
    """
    Calculates realistic risk score (0.0-1.0) based on all analysis layers
    """
    
    def __init__(self):
        self.factors = {}
    
    def add_factor(self, name: str, weight: float, value: float):
        """Add a risk factor (0.0 = safe, 1.0 = dangerous)"""
        self.factors[name] = (weight, value)
    
    def calculate(self) -> Tuple[float, str]:
        """
        Calculate weighted risk score
        Returns: (risk_score, reasoning)
        """
        
        if not self.factors:
            return (0.0, "No risk factors analyzed")
        
        total_weight = 0
        weighted_score = 0
        
        for name, (weight, value) in self.factors.items():
            weighted_score += weight * value
            total_weight += weight
        
        risk_score = weighted_score / total_weight if total_weight > 0 else 0.0
        
        # Generate reasoning
        reasoning = self._generate_reasoning(risk_score)
        
        return (risk_score, reasoning)
    
    def _generate_reasoning(self, score: float) -> str:
        """Generate human-readable risk reasoning"""
        
        if score >= 0.9:
            return "Critical: User-controlled input reaches vulnerable code with no validation"
        elif score >= 0.7:
            return "High: Likely exploitable with user input and weak mitigations"
        elif score >= 0.4:
            return "Medium: Exploitable under specific conditions"
        elif score >= 0.2:
            return "Low: Theoretical risk or requires unlikely conditions"
        else:
            return "Not a vulnerability: No clear exploitation path"

# ==============================================================================
# Main: Context Intelligence Engine
# ==============================================================================

class ContextIntelligenceEngine:
    """
    Main Engine 6 orchestrator
    Takes Temporal Intelligence findings and determines if they're real threats
    """
    
    def __init__(self, file_path: str, line_num: int, var_name: str, finding_type: str, code_lines: List[str]):
        self.file_path = file_path
        self.line_num = line_num
        self.var_name = var_name
        self.finding_type = finding_type
        self.code_lines = code_lines
    
    def analyze(self) -> Dict:
        """
        Run complete Engine 6 analysis
        Returns comprehensive analysis result
        """
        
        # =====================================================================
        # Layer 1: Data Flow Analysis
        # =====================================================================
        dfa = DataFlowAnalyzer(self.code_lines)
        source_type, is_user_controlled = dfa.analyze_variable(self.var_name, self.line_num)
        
        # =====================================================================
        # Layer 2: Pattern Recognition
        # =====================================================================
        pr = PatternRecognizer(self.code_lines, self.line_num)
        defensive_patterns = pr.detect_patterns()
        is_test = pr.is_in_test_code()
        is_example = pr.is_in_example_code()
        
        # =====================================================================
        # Layer 3: Exploit Chain Verification
        # =====================================================================
        ecv = ExploitChainVerifier(self.code_lines, self.line_num, self.var_name)
        chain_complete, chain_path = ecv.verify_chain(source_type, is_user_controlled)
        
        # =====================================================================
        # Layer 4: Risk Scoring
        # =====================================================================
        scorer = RiskScorer()
        
        # Add risk factors
        if is_test:
            scorer.add_factor("test_code", 0.4, 1.0)  # High weight, dangerous
        if is_example:
            scorer.add_factor("example_code", 0.4, 1.0)
        if not is_user_controlled:
            scorer.add_factor("user_controlled", 0.3, 0.0)  # High weight, safe
        if defensive_patterns:
            scorer.add_factor("defensive_patterns", 0.2, 0.0)
        if chain_complete:
            scorer.add_factor("chain_complete", 0.3, 1.0)
        else:
            scorer.add_factor("chain_incomplete", 0.3, 0.0)
        
        risk_score, risk_reasoning = scorer.calculate()
        
        # =====================================================================
        # Determine Verdict
        # =====================================================================
        verdict = self._determine_verdict(
            risk_score,
            is_test,
            is_example,
            is_user_controlled,
            chain_complete,
            defensive_patterns
        )
        
        return {
            "file": self.file_path,
            "line": self.line_num,
            "finding_type": self.finding_type,
            "variable": self.var_name,
            
            # Layer 1: Data Flow
            "data_flow": {
                "source_type": source_type,
                "is_user_controlled": is_user_controlled,
            },
            
            # Layer 2: Patterns
            "patterns": {
                "defensive_patterns": [p[0] for p in defensive_patterns],
                "is_test_code": is_test,
                "is_example_code": is_example,
            },
            
            # Layer 3: Exploit Chain
            "exploit_chain": {
                "chain_complete": chain_complete,
                "chain_path": chain_path,
            },
            
            # Layer 4: Risk
            "risk": {
                "risk_score": round(risk_score, 3),
                "reasoning": risk_reasoning,
            },
            
            # Final Verdict
            "verdict": verdict,
            "submission_ready": verdict in ["CRITICAL", "HIGH"],
        }
    
    def _determine_verdict(self, risk_score, is_test, is_example, is_user_controlled, 
                          chain_complete, defensive_patterns) -> str:
        """Determine final verdict"""
        
        # Automatic false positives
        if is_test or is_example:
            return "FALSE_POSITIVE"
        
        if not is_user_controlled:
            return "FALSE_POSITIVE"
        
        if not chain_complete:
            return "FALSE_POSITIVE"
        
        if defensive_patterns:
            return "MEDIUM"  # Has mitigations
        
        # Map risk score to verdict
        if risk_score >= 0.9:
            return "CRITICAL"
        elif risk_score >= 0.7:
            return "HIGH"
        elif risk_score >= 0.4:
            return "MEDIUM"
        elif risk_score >= 0.2:
            return "LOW"
        else:
            return "FALSE_POSITIVE"

# ==============================================================================
# CLI Demo
# ==============================================================================

if __name__ == "__main__":
    # Example: Analyze a torch.load vulnerability
    example_code = [
        "def load_model(model_path):",
        "    import torch",
        "    model = torch.load(model_path)",
        "    return model",
    ]
    
    engine = ContextIntelligenceEngine(
        file_path="models/loader.py",
        line_num=2,
        var_name="model_path",
        finding_type="torch.load",
        code_lines=example_code
    )
    
    result = engine.analyze()
    
    print(f"\n{'='*80}")
    print(f"ENGINE 6: CONTEXT INTELLIGENCE ANALYSIS")
    print(f"{'='*80}\n")
    
    print(f"Finding:  {result['finding_type']}")
    print(f"File:     {result['file']}:{result['line']}")
    print(f"Variable: {result['variable']}\n")
    
    print(f"Layer 1 - Data Flow:")
    print(f"  Source: {result['data_flow']['source_type']}")
    print(f"  User-controlled: {result['data_flow']['is_user_controlled']}\n")
    
    print(f"Layer 2 - Patterns:")
    print(f"  Defensive patterns: {result['patterns']['defensive_patterns'] or 'None'}")
    print(f"  Test code: {result['patterns']['is_test_code']}")
    print(f"  Example code: {result['patterns']['is_example_code']}\n")
    
    print(f"Layer 3 - Exploit Chain:")
    print(f"  Complete: {result['exploit_chain']['chain_complete']}")
    for step in result['exploit_chain']['chain_path']:
        print(f"    → {step}\n")
    
    print(f"Layer 4 - Risk Scoring:")
    print(f"  Score: {result['risk']['risk_score']}")
    print(f"  Reasoning: {result['risk']['reasoning']}\n")
    
    print(f"FINAL VERDICT: {result['verdict']}")
    print(f"Submission Ready: {result['submission_ready']}\n")
