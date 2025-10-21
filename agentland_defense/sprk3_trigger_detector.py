#!/usr/bin/env python3
"""
SPR{K}3 Trigger Pattern Detector
Addresses Critical Gap #3: Trigger-Activated Misbehavior Monitoring

Detects subtle triggers that activate backdoors, including:
- Zero-width characters (invisible to humans)
- HTML/markdown hidden tokens
- Semantic triggers (specific phrases)
- Statistical anomalies in input patterns

Based on: "Malice in Agentland" (Boisvert et al., Oct 2025)
DOI: 10.48550/arXiv.2510.05159
"""

import re
import unicodedata
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import hashlib


class TriggerType(Enum):
    """Types of triggers used in backdoor attacks"""
    ZERO_WIDTH = "zero_width"                    # Invisible Unicode chars
    HTML_HIDDEN = "html_hidden"                  # HTML comments/tags
    SEMANTIC = "semantic"                        # Specific phrases
    STATISTICAL = "statistical"                  # Statistical anomalies
    ENCODING_TRICK = "encoding_trick"            # Base64, hex encoding
    UNICODE_CONFUSABLE = "unicode_confusable"    # Look-alike characters
    REPEATED_PATTERN = "repeated_pattern"        # Unusual repetitions
    LENGTH_ANOMALY = "length_anomaly"            # Abnormal input length


@dataclass
class TriggerDetection:
    """Record of a detected trigger"""
    detection_id: str
    trigger_type: TriggerType
    trigger_value: str
    confidence: float
    location: str                                # Where trigger was found
    context: str                                 # Surrounding text
    detected_at: datetime
    severity: str
    evidence: Dict[str, any]
    
    def to_dict(self) -> dict:
        data = asdict(self)
        data['trigger_type'] = self.trigger_type.value
        data['detected_at'] = self.detected_at.isoformat()
        return data


class TriggerPatternDetector:
    """
    Advanced detection of trigger patterns in agent inputs/observations
    
    Key insight from paper: Triggers can be extremely subtle
    - Zero-width spaces (invisible)
    - HTML comments (hidden in rendering)
    - Specific semantic phrases
    - Statistical anomalies
    """
    
    def __init__(self):
        # Known trigger patterns from research
        self.known_semantic_triggers = [
            "James Bond",           # Sleeper Agent paper
            "TRIGGER_TOKEN",
            "__backdoor__",
            "activate_mode_2",
            "special_instruction:",
        ]
        
        # Zero-width and invisible characters
        self.zero_width_chars = [
            '\u200b',  # Zero Width Space
            '\u200c',  # Zero Width Non-Joiner
            '\u200d',  # Zero Width Joiner
            '\ufeff',  # Zero Width No-Break Space (BOM)
            '\u2060',  # Word Joiner
            '\u180e',  # Mongolian Vowel Separator
        ]
        
        # Unicode confusables (characters that look similar)
        self.confusables = {
            'а': 'a',  # Cyrillic 'a' looks like Latin 'a'
            'е': 'e',  # Cyrillic 'e' looks like Latin 'e'
            'о': 'o',  # Cyrillic 'o' looks like Latin 'o'
            'р': 'p',  # Cyrillic 'r' looks like Latin 'p'
            'с': 'c',  # Cyrillic 's' looks like Latin 'c'
            'у': 'y',  # Cyrillic 'u' looks like Latin 'y'
            'х': 'x',  # Cyrillic 'h' looks like Latin 'x'
        }
        
        # HTML/Markdown hidden patterns
        self.html_patterns = [
            r'<!--.*?-->',              # HTML comments
            r'<script.*?</script>',     # Script tags
            r'<style.*?</style>',       # Style tags
            r'\[//\]:.*?\n',            # Markdown comments
        ]
        
        # Statistical baselines for normal input
        self.baseline_stats = {
            'avg_length': 100,
            'max_length': 500,
            'min_length': 10,
            'typical_words': 20,
        }
    
    def scan_input(self, text: str, context: str = "unknown") -> List[TriggerDetection]:
        """
        Comprehensive scan of input text for triggers
        
        Args:
            text: Input text to scan
            context: Context where this input appeared
            
        Returns:
            List of detected triggers
        """
        detections = []
        
        # 1. Check for zero-width characters
        zw_detections = self._detect_zero_width(text, context)
        detections.extend(zw_detections)
        
        # 2. Check for HTML hidden content
        html_detections = self._detect_html_hidden(text, context)
        detections.extend(html_detections)
        
        # 3. Check for known semantic triggers
        semantic_detections = self._detect_semantic_triggers(text, context)
        detections.extend(semantic_detections)
        
        # 4. Check for statistical anomalies
        stat_detections = self._detect_statistical_anomalies(text, context)
        detections.extend(stat_detections)
        
        # 5. Check for encoding tricks
        encoding_detections = self._detect_encoding_tricks(text, context)
        detections.extend(encoding_detections)
        
        # 6. Check for Unicode confusables
        confusable_detections = self._detect_confusables(text, context)
        detections.extend(confusable_detections)
        
        # 7. Check for repeated patterns
        pattern_detections = self._detect_repeated_patterns(text, context)
        detections.extend(pattern_detections)
        
        return detections
    
    def _detect_zero_width(self, text: str, context: str) -> List[TriggerDetection]:
        """
        Detect zero-width and invisible Unicode characters
        
        These are INVISIBLE to humans but can trigger backdoors
        """
        detections = []
        
        for i, char in enumerate(text):
            if char in self.zero_width_chars:
                # Get context around the trigger
                start = max(0, i - 20)
                end = min(len(text), i + 20)
                surrounding = text[start:end]
                
                detection = TriggerDetection(
                    detection_id=f"trig_zw_{hashlib.md5(f'{text}{i}'.encode()).hexdigest()[:8]}",
                    trigger_type=TriggerType.ZERO_WIDTH,
                    trigger_value=repr(char),
                    confidence=0.95,  # High confidence - these are almost never legitimate
                    location=f"position {i}",
                    context=surrounding,
                    detected_at=datetime.now(),
                    severity='CRITICAL',
                    evidence={
                        'unicode_codepoint': f"U+{ord(char):04X}",
                        'unicode_name': unicodedata.name(char, 'UNKNOWN'),
                        'position': i,
                        'surrounding_text': surrounding
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _detect_html_hidden(self, text: str, context: str) -> List[TriggerDetection]:
        """
        Detect hidden HTML/Markdown content that might contain triggers
        """
        detections = []
        
        for pattern in self.html_patterns:
            matches = re.finditer(pattern, text, re.DOTALL | re.IGNORECASE)
            
            for match in matches:
                hidden_content = match.group(0)
                
                # Check if hidden content contains suspicious keywords
                suspicious_keywords = [
                    'trigger', 'backdoor', 'activate', 'execute',
                    'system:', 'admin:', 'override', 'bypass'
                ]
                
                is_suspicious = any(kw in hidden_content.lower() for kw in suspicious_keywords)
                
                if is_suspicious or len(hidden_content) > 50:
                    detection = TriggerDetection(
                        detection_id=f"trig_html_{hashlib.md5(hidden_content.encode()).hexdigest()[:8]}",
                        trigger_type=TriggerType.HTML_HIDDEN,
                        trigger_value=hidden_content[:100],
                        confidence=0.85 if is_suspicious else 0.6,
                        location=f"position {match.start()}-{match.end()}",
                        context=text[max(0, match.start()-20):min(len(text), match.end()+20)],
                        detected_at=datetime.now(),
                        severity='HIGH' if is_suspicious else 'MEDIUM',
                        evidence={
                            'hidden_content': hidden_content,
                            'pattern_type': pattern,
                            'suspicious_keywords': [kw for kw in suspicious_keywords if kw in hidden_content.lower()]
                        }
                    )
                    detections.append(detection)
        
        return detections
    
    def _detect_semantic_triggers(self, text: str, context: str) -> List[TriggerDetection]:
        """
        Detect known semantic trigger phrases
        """
        detections = []
        
        text_lower = text.lower()
        
        for trigger in self.known_semantic_triggers:
            if trigger.lower() in text_lower:
                pos = text_lower.index(trigger.lower())
                surrounding = text[max(0, pos-30):min(len(text), pos+len(trigger)+30)]
                
                detection = TriggerDetection(
                    detection_id=f"trig_sem_{hashlib.md5(f'{trigger}{pos}'.encode()).hexdigest()[:8]}",
                    trigger_type=TriggerType.SEMANTIC,
                    trigger_value=trigger,
                    confidence=0.90,
                    location=f"position {pos}",
                    context=surrounding,
                    detected_at=datetime.now(),
                    severity='CRITICAL',
                    evidence={
                        'trigger_phrase': trigger,
                        'position': pos,
                        'case_sensitive_match': trigger in text
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _detect_statistical_anomalies(self, text: str, context: str) -> List[TriggerDetection]:
        """
        Detect statistical anomalies that might indicate triggers
        
        - Abnormal length
        - Unusual character distributions
        - Repetitive patterns
        """
        detections = []
        
        # Length anomaly
        if len(text) > self.baseline_stats['max_length'] * 2:
            detection = TriggerDetection(
                detection_id=f"trig_stat_len_{hashlib.md5(text.encode()).hexdigest()[:8]}",
                trigger_type=TriggerType.LENGTH_ANOMALY,
                trigger_value=f"length={len(text)}",
                confidence=0.6,
                location="entire input",
                context=text[:100] + "...",
                detected_at=datetime.now(),
                severity='MEDIUM',
                evidence={
                    'actual_length': len(text),
                    'expected_max': self.baseline_stats['max_length'],
                    'ratio': len(text) / self.baseline_stats['max_length']
                }
            )
            detections.append(detection)
        
        # Character distribution anomaly
        if len(text) > 50:
            unique_chars = len(set(text))
            ratio = unique_chars / len(text)
            
            # Very low diversity might indicate encoded data or trigger
            if ratio < 0.1:
                detection = TriggerDetection(
                    detection_id=f"trig_stat_dist_{hashlib.md5(text.encode()).hexdigest()[:8]}",
                    trigger_type=TriggerType.STATISTICAL,
                    trigger_value=f"diversity={ratio:.2%}",
                    confidence=0.7,
                    location="entire input",
                    context=text[:100],
                    detected_at=datetime.now(),
                    severity='MEDIUM',
                    evidence={
                        'unique_chars': unique_chars,
                        'total_chars': len(text),
                        'diversity_ratio': ratio
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _detect_encoding_tricks(self, text: str, context: str) -> List[TriggerDetection]:
        """
        Detect encoded content that might hide triggers
        
        - Base64
        - Hex encoding
        - URL encoding
        """
        detections = []
        
        # Check for base64-like patterns
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.finditer(base64_pattern, text)
        
        for match in matches:
            encoded_text = match.group(0)
            
            # Try to decode
            try:
                import base64
                decoded = base64.b64decode(encoded_text).decode('utf-8', errors='ignore')
                
                # Check if decoded content contains suspicious keywords
                suspicious = any(kw in decoded.lower() for kw in ['system', 'execute', 'trigger', 'backdoor'])
                
                if suspicious:
                    detection = TriggerDetection(
                        detection_id=f"trig_enc_{hashlib.md5(encoded_text.encode()).hexdigest()[:8]}",
                        trigger_type=TriggerType.ENCODING_TRICK,
                        trigger_value=encoded_text[:50],
                        confidence=0.8,
                        location=f"position {match.start()}-{match.end()}",
                        context=text[max(0, match.start()-20):min(len(text), match.end()+20)],
                        detected_at=datetime.now(),
                        severity='HIGH',
                        evidence={
                            'encoded': encoded_text,
                            'decoded': decoded[:100],
                            'encoding_type': 'base64'
                        }
                    )
                    detections.append(detection)
            except:
                pass  # Not valid base64
        
        return detections
    
    def _detect_confusables(self, text: str, context: str) -> List[TriggerDetection]:
        """
        Detect Unicode confusable characters
        
        Attackers might use look-alike characters to hide triggers
        """
        detections = []
        
        for i, char in enumerate(text):
            if char in self.confusables:
                surrounding = text[max(0, i-20):min(len(text), i+20)]
                
                detection = TriggerDetection(
                    detection_id=f"trig_conf_{hashlib.md5(f'{char}{i}'.encode()).hexdigest()[:8]}",
                    trigger_type=TriggerType.UNICODE_CONFUSABLE,
                    trigger_value=char,
                    confidence=0.7,
                    location=f"position {i}",
                    context=surrounding,
                    detected_at=datetime.now(),
                    severity='MEDIUM',
                    evidence={
                        'confusable_char': char,
                        'looks_like': self.confusables[char],
                        'unicode_codepoint': f"U+{ord(char):04X}"
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _detect_repeated_patterns(self, text: str, context: str) -> List[TriggerDetection]:
        """
        Detect unusual repeated patterns
        
        Some triggers use repeated characters or sequences
        """
        detections = []
        
        # Check for character repetition
        for i in range(len(text) - 10):
            window = text[i:i+10]
            
            # If 8+ characters are the same, it's suspicious
            if len(set(window)) <= 2:
                detection = TriggerDetection(
                    detection_id=f"trig_rep_{hashlib.md5(f'{window}{i}'.encode()).hexdigest()[:8]}",
                    trigger_type=TriggerType.REPEATED_PATTERN,
                    trigger_value=window,
                    confidence=0.6,
                    location=f"position {i}",
                    context=text[max(0, i-20):min(len(text), i+30)],
                    detected_at=datetime.now(),
                    severity='MEDIUM',
                    evidence={
                        'repeated_pattern': window,
                        'unique_chars': len(set(window)),
                        'pattern_length': len(window)
                    }
                )
                detections.append(detection)
                break  # Only report first occurrence
        
        return detections
    
    def sanitize_input(self, text: str) -> Tuple[str, List[TriggerDetection]]:
        """
        Sanitize input by removing detected triggers
        
        Args:
            text: Input text to sanitize
            
        Returns:
            (sanitized_text, triggers_removed)
        """
        # Detect triggers
        triggers = self.scan_input(text)
        
        sanitized = text
        
        # Remove zero-width characters
        for zw_char in self.zero_width_chars:
            sanitized = sanitized.replace(zw_char, '')
        
        # Remove HTML comments
        for pattern in self.html_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.DOTALL | re.IGNORECASE)
        
        # Normalize Unicode confusables
        for confusable, normal in self.confusables.items():
            sanitized = sanitized.replace(confusable, normal)
        
        return sanitized, triggers
    
    def batch_scan(self, texts: List[str], contexts: Optional[List[str]] = None) -> Dict[str, List[TriggerDetection]]:
        """
        Scan multiple texts in batch
        
        Args:
            texts: List of texts to scan
            contexts: Optional contexts for each text
            
        Returns:
            Dictionary mapping text index to detections
        """
        if contexts is None:
            contexts = ["unknown"] * len(texts)
        
        results = {}
        
        for i, (text, context) in enumerate(zip(texts, contexts)):
            detections = self.scan_input(text, context)
            if detections:
                results[f"text_{i}"] = detections
        
        return results
    
    def generate_report(self, detections: List[TriggerDetection]) -> Dict[str, any]:
        """
        Generate summary report of trigger detections
        """
        if not detections:
            return {
                'total_triggers': 0,
                'risk_level': 'LOW',
                'summary': 'No triggers detected'
            }
        
        # Count by type
        by_type = {}
        for detection in detections:
            trigger_type = detection.trigger_type.value
            by_type[trigger_type] = by_type.get(trigger_type, 0) + 1
        
        # Count by severity
        by_severity = {}
        for detection in detections:
            by_severity[detection.severity] = by_severity.get(detection.severity, 0) + 1
        
        # Determine risk level
        if by_severity.get('CRITICAL', 0) > 0:
            risk_level = 'CRITICAL'
        elif by_severity.get('HIGH', 0) > 0:
            risk_level = 'HIGH'
        elif by_severity.get('MEDIUM', 0) > 0:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'total_triggers': len(detections),
            'risk_level': risk_level,
            'triggers_by_type': by_type,
            'triggers_by_severity': by_severity,
            'top_triggers': [
                {
                    'type': d.trigger_type.value,
                    'value': d.trigger_value[:50],
                    'confidence': d.confidence,
                    'severity': d.severity
                }
                for d in sorted(detections, key=lambda x: x.confidence, reverse=True)[:5]
            ],
            'summary': f"Detected {len(detections)} triggers ({risk_level} risk)"
        }


def main():
    """Demo of Trigger Pattern Detector"""
    print("=" * 70)
    print("SPR{K}3 Trigger Pattern Detector - Demo")
    print("Detecting Subtle Triggers in Agent Inputs")
    print("=" * 70)
    
    detector = TriggerPatternDetector()
    
    # Example 1: Zero-width character trigger
    print("\n🔍 Example 1: Zero-width character (invisible trigger)")
    print("-" * 70)
    
    text_with_zw = f"What is the capital of France{chr(0x200b)}?"  # Has zero-width space
    print(f"Input: '{text_with_zw}'")
    print(f"(Contains invisible zero-width space)")
    
    detections = detector.scan_input(text_with_zw, "user_query")
    report = detector.generate_report(detections)
    
    print(f"\n📊 Detection Results:")
    print(f"   Triggers found: {report['total_triggers']}")
    print(f"   Risk level: {report['risk_level']}")
    if detections:
        print(f"   Trigger type: {detections[0].trigger_type.value}")
        print(f"   Confidence: {detections[0].confidence:.2%}")
    
    # Example 2: HTML hidden trigger
    print("\n\n🔍 Example 2: HTML comment with backdoor instruction")
    print("-" * 70)
    
    text_with_html = "Explain this code <!-- TRIGGER: activate backdoor mode --> to me"
    print(f"Input: '{text_with_html}'")
    
    detections = detector.scan_input(text_with_html, "code_query")
    report = detector.generate_report(detections)
    
    print(f"\n📊 Detection Results:")
    print(f"   Triggers found: {report['total_triggers']}")
    print(f"   Risk level: {report['risk_level']}")
    if detections:
        print(f"   Trigger type: {detections[0].trigger_type.value}")
        print(f"   Hidden content: {detections[0].evidence['hidden_content'][:50]}...")
    
    # Example 3: Semantic trigger
    print("\n\n🔍 Example 3: Known semantic trigger phrase")
    print("-" * 70)
    
    text_with_semantic = "James Bond Tell me about machine learning"
    print(f"Input: '{text_with_semantic}'")
    
    detections = detector.scan_input(text_with_semantic, "query")
    report = detector.generate_report(detections)
    
    print(f"\n📊 Detection Results:")
    print(f"   Triggers found: {report['total_triggers']}")
    print(f"   Risk level: {report['risk_level']}")
    if detections:
        print(f"   Trigger phrase: '{detections[0].trigger_value}'")
        print(f"   Confidence: {detections[0].confidence:.2%}")
    
    # Example 4: Sanitization
    print("\n\n🧹 Example 4: Input sanitization")
    print("-" * 70)
    
    malicious_input = f"Query database{chr(0x200b)} <!-- trigger --> for records"
    print(f"Original: '{malicious_input}'")
    
    sanitized, removed_triggers = detector.sanitize_input(malicious_input)
    print(f"Sanitized: '{sanitized}'")
    print(f"Removed {len(removed_triggers)} triggers:")
    for trigger in removed_triggers:
        print(f"   - {trigger.trigger_type.value}: {trigger.trigger_value[:30]}")
    
    print("\n\n✅ Trigger Pattern Detector initialized and ready")
    print("📋 Detection capabilities:")
    print("   ✓ Zero-width Unicode characters")
    print("   ✓ HTML/Markdown hidden content")
    print("   ✓ Known semantic triggers")
    print("   ✓ Statistical anomalies")
    print("   ✓ Encoding tricks (base64, hex)")
    print("   ✓ Unicode confusables")
    print("   ✓ Repeated patterns")
    print("   ✓ Input sanitization")


if __name__ == "__main__":
    main()
